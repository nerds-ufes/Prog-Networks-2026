
# bpf_cubic.c — TCP CUBIC via eBPF `struct_ops`

Implementação do algoritmo de controle de congestionamento TCP **CUBIC** como um programa eBPF usando a interface `struct_ops`. Permite carregar, registrar e configurar dinamicamente o CUBIC no kernel Linux sem recompilar ou substituir módulos — e ajustar seus parâmetros em tempo real via mapa eBPF.

> ⚠️ Esta implementação é derivada do `tcp_cubic.c` do kernel, mas **não é idêntica** a ele. O propósito principal é testar a infraestrutura de eBPF `struct_ops` para controle de congestionamento TCP. Consulte as [diferenças em relação ao kernel](#diferenças-em-relação-ao-tcp_cubicc-do-kernel) para detalhes.

---

## Sumário

1. [Visão geral](#1-visão-geral)
2. [Pré-requisitos](#2-pré-requisitos)
3. [Compilação](#3-compilação)
4. [Registro e ativação](#4-registro-e-ativação)
5. [Arquitetura do código](#5-arquitetura-do-código)
   - [Includes e licença](#includes-e-licença)
   - [Parâmetros globais](#parâmetros-globais)
   - [Estrutura de estado por conexão (`bpf_bictcp`)](#estrutura-de-estado-por-conexão-bpf_bictcp)
   - [Mapa eBPF `cubic_cfg`](#mapa-ebpf-cubic_cfg)
   - [Funções auxiliares de parâmetros](#funções-auxiliares-de-parâmetros)
   - [Funções de métricas de RTT](#funções-de-métricas-de-rtt)
   - [Funções internas do algoritmo](#funções-internas-do-algoritmo)
   - [Callbacks `struct_ops` registrados](#callbacks-struct_ops-registrados)
6. [Fluxo do algoritmo CUBIC](#6-fluxo-do-algoritmo-cubic)
7. [Configuração dinâmica via mapa eBPF](#7-configuração-dinâmica-via-mapa-ebpf)
8. [Lógica customizada de reset em `bpf_cubic_state`](#8-lógica-customizada-de-reset-em-bpf_cubic_state)
9. [Diferenças em relação ao `tcp_cubic.c` do kernel](#9-diferenças-em-relação-ao-tcp_cubicc-do-kernel)
10. [Remoção do algoritmo](#10-remoção-do-algoritmo)
11. [Notas e observações](#11-notas-e-observações)

---

## 1. Visão geral

O CUBIC é o algoritmo de controle de congestionamento padrão do Linux desde o kernel 2.6.19. Sua característica principal é usar uma **função cúbica** para calcular o crescimento da janela de congestionamento (`cwnd`), tornando o crescimento independente do RTT e mais justo em redes de alta velocidade.

Esta implementação eBPF replica o comportamento do CUBIC com três diferenças intencionais:

- Os parâmetros `beta`, `bic_scale` e `mult_rtt` são **mutáveis em tempo real** via mapa eBPF, sem reinicialização.
- O cálculo interno usa **resolução em microssegundos** (`usec`) em vez de jiffies.
- A lógica de reset em caso de perda (`bpf_cubic_state`) inclui uma **condição extra de RTT elevado**, controlada pelo parâmetro `mult_rtt`.

---

## 2. Pré-requisitos

| Requisito              | Detalhe                                      |
|------------------------|----------------------------------------------|
| Kernel Linux           | ≥ 6.1 (recomendado ≥ 6.5)                   |
| Suporte a BTF          | Necessário para `vmlinux.h` e CO-RE          |
| `clang-14` / `llvm-14` | Compilador para alvo BPF                     |
| `libbpf-dev`           | Biblioteca BPF para helpers e macros         |
| `bpftool`              | Para registro, inspeção e atualização do map |
| `vmlinux.h`            | Gerado a partir do BTF do kernel em execução |
| `bpf_tracing_net.h`    | Header auxiliar do projeto (local)           |

Gere o `vmlinux.h` antes de compilar:

```bash
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

---

## 3. Compilação

```bash
sudo clang-14 -target bpf -D__TARGET_ARCH_x86 -g -O2 -Wall -c bpf_cubic.c -o bpf_cubic.o
```

| Flag                    | Finalidade                                         |
|-------------------------|----------------------------------------------------|
| `-target bpf`           | Compila para arquitetura BPF                       |
| `-D__TARGET_ARCH_x86`   | Define arquitetura alvo para macros de tracing     |
| `-g`                    | Inclui informações de debug (BTF)                  |
| `-O2`                   | Otimização necessária para satisfazer o verificador|
| `-Wall`                 | Ativa todos os warnings                            |

Verifique o ELF gerado:

```bash
llvm-objdump -h bpf_cubic.o
```

Seções esperadas: `.struct_ops`, `.maps`, `.BTF`.

---

## 4. Registro e ativação

### Registrar o CCA no kernel

```bash
sudo bpftool struct_ops register bpf_cubic.o
# Saída: Registered tcp_congestion_ops cubic id <N>
```

### Confirmar registro

```bash
sudo bpftool struct_ops show
```

### Ativar como algoritmo padrão do sistema

```bash
sudo sysctl -w net.ipv4.tcp_congestion_control=bpf_cubic
```

> ⚠️ Apenas novas conexões TCP usarão o `bpf_cubic`. Conexões existentes mantêm o algoritmo anterior.

### Remover

```bash
sudo bpftool struct_ops unregister name cubic
```

---

## 5. Arquitetura do código

### Includes e licença

```c
#include "vmlinux.h"             // Tipos e structs do kernel via BTF
#include <bpf/bpf_helpers.h>     // Macros SEC(), BPF_PROG(), helpers
#include <bpf/bpf_core_read.h>   // CO-RE: leitura portável de structs do kernel
#include <bpf/bpf_tracing.h>     // Macros de tracing BPF
#include "bpf_tracing_net.h"     // Helpers de rede (local)

char _license[] SEC("license") = "GPL";
```

> ℹ️ `bpf_helpers.h` e `bpf_core_read.h` aparecem duplicados no arquivo — isso não causa erro de compilação mas pode ser limpo.

---

### Parâmetros globais

Parâmetros de comportamento definidos como variáveis estáticas — equivalentes aos parâmetros de módulo do `tcp_cubic.ko`:

| Variável               | Valor padrão                          | Função                                              |
|------------------------|---------------------------------------|-----------------------------------------------------|
| `fast_convergence`     | `1` (ativo)                           | Reduz `wmax` mais agressivamente para novos fluxos  |
| `initial_ssthresh`     | `0` (desativado)                      | Slow start threshold inicial (0 = sem limite)       |
| `tcp_friendliness`     | `1` (ativo)                           | Garante fairness com fluxos TCP Reno                |
| `hystart`              | `1` (ativo)                           | Habilita HyStart (slow start híbrido)               |
| `hystart_detect`       | `ACK_TRAIN \| DELAY`                  | Métodos de detecção do HyStart                     |
| `hystart_low_window`   | `16`                                  | Janela mínima para ativar HyStart                   |
| `hystart_ack_delta_us` | `2000` µs                             | Delta máximo entre ACKs para detecção ACK train     |

---

### Estrutura de estado por conexão (`bpf_bictcp`)

Mantém o estado do CUBIC **por socket TCP**. Armazenada na área de dados privados do socket via `inet_csk_ca(sk)`.

```c
struct bpf_bictcp {
    __u32 cnt;              // Incrementa cwnd a cada N ACKs
    __u32 last_max_cwnd;    // Último cwnd máximo antes de redução
    __u32 last_cwnd;        // Último cwnd registrado
    __u32 last_time;        // Timestamp da última atualização
    __u32 bic_origin_point; // Ponto de origem da função cúbica
    __u32 bic_K;            // Tempo até atingir wmax (em unidades BICTCP_HZ)
    __u32 delay_min;        // RTT mínimo histórico (µs)
    __u32 epoch_start;      // Início do epoch atual
    __u32 ack_cnt;          // Contador de ACKs recebidos
    __u32 tcp_cwnd;         // Estimativa do cwnd TCP Reno (para tcp_friendliness)
    __u8  sample_cnt;       // Número de amostras de RTT no round atual
    __u8  found;            // Ponto de saída do slow start encontrado?
    __u32 round_start;      // Início do round atual
    __u32 end_seq;          // Sequência final do round
    __u32 last_ack;         // Timestamp do último ACK (HyStart ACK train)
    __u32 curr_rtt;         // RTT mínimo do round atual (µs)
};
```

---

### Mapa eBPF `cubic_cfg`

Mapa do tipo `ARRAY` com **uma única entrada** que expõe os parâmetros do CUBIC para leitura e escrita em tempo real, sem recarregar o programa:

```c
struct cubic_config {
    __u32 beta;      // Fator de redução do cwnd (escalonado por 1024)
    __u32 bic_scale; // Escala da função cúbica
    __u32 mult_rtt;  // Multiplicador de RTT para reset em estado de Loss
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cubic_config);
} cubic_cfg SEC(".maps");
```

| Campo       | Default | Mínimo | Máximo | Efeito                                         |
|-------------|---------|--------|--------|------------------------------------------------|
| `beta`      | `717`   | —      | `1023` | Fração de redução do cwnd após perda (`717/1024 ≈ 0.7`) |
| `bic_scale` | `41`    | `10`   | `60`   | Agressividade do crescimento cúbico            |
| `mult_rtt`  | `5`     | —      | —      | Limiar de RTT elevado para reset duplo         |

> ℹ️ Se o mapa não for encontrado ou um campo for `0`, o código usa automaticamente os valores `#define` padrão — o mapa nunca é obrigatório para operação.

---

### Funções auxiliares de parâmetros

Três funções `__always_inline` fazem a leitura segura do mapa, aplicando defaults e clamps:

#### `cubic_beta()`
Retorna o valor de `beta` do mapa ou `717` se ausente/zero.

#### `cubic_bic_scale()`
Retorna o valor de `bic_scale` do mapa, **forçando o valor para o intervalo `[10, 60]`** independentemente do que for escrito no mapa.

#### `cubic_mult_rtt()`
Retorna o multiplicador de RTT do mapa ou `5` se ausente/zero.

#### `cubic_beta_scale(beta)`
Função derivada — calcula o fator de escala usado na lógica de TCP friendliness:

```
beta_scale = 8 * (1024 + beta) / (3 * (1024 - beta))
```

---

### Funções de métricas de RTT

Bloco de funções utilitárias para cálculo e exposição de métricas de RTT. São funções de **leitura pura** — não modificam o estado do socket.

| Função                        | Retorno                  | Descrição                                              |
|-------------------------------|--------------------------|--------------------------------------------------------|
| `calculate_rtt_metrics()`     | `struct rtt_metrics`     | Retorna min_rtt, variação absoluta/relativa e flag de RTT elevado (>25% do mínimo) |
| `get_rtt_stats()`             | via ponteiros            | Versão alternativa com saída por ponteiros             |
| `get_current_rtt_variation()` | `__u32`                  | Retorna apenas a variação atual do RTT                 |
| `get_historical_min_rtt()`    | `__u32`                  | Retorna o RTT mínimo histórico do socket               |

```c
struct rtt_metrics {
    __u32 min_rtt;            // RTT mínimo histórico (delay_min)
    __u32 current_min;        // Menor RTT do round atual
    __u32 absolute_variation; // current_min - min_rtt (µs)
    __u32 relative_variation; // variação em % do mínimo
    __u8  is_elevated;        // 1 se RTT > min_rtt * 1.25
};
```

> ℹ️ Essas funções estão disponíveis mas **não são chamadas por nenhum callback ativo** — foram projetadas para uso em monitoramento futuro ou em `bpf_cubic_state` (ver código comentado).

---

### Funções internas do algoritmo

| Função                  | Descrição                                                          |
|-------------------------|--------------------------------------------------------------------|
| `bictcp_reset()`        | Zera todo o estado do `bpf_bictcp` (chamada no init e em Loss)    |
| `bictcp_hystart_reset()`| Reinicia o estado do HyStart para o próximo round                 |
| `bictcp_clock_us()`     | Retorna o timestamp atual em µs via `tcp_mstamp`                  |
| `cubic_root()`          | Calcula a raiz cúbica usando lookup table + uma iteração de Newton-Raphson (erro médio ~0.195%) |
| `bictcp_update()`       | Calcula o novo `cnt` (controla o crescimento do cwnd) com base na função cúbica e TCP friendliness |
| `hystart_update()`      | Detecta fim do slow start via ACK train ou aumento de delay       |
| `hystart_ack_delay()`   | Calcula o delay mínimo esperado de ACKs considerando TSO/GRO      |
| `fls64()`               | Find Last Set bit em inteiro de 64 bits (usado por `cubic_root`)  |

---

### Callbacks `struct_ops` registrados

Esses são os **pontos de entrada do kernel** para o algoritmo. Cada um é marcado com `SEC("struct_ops")` e registrado na struct `tcp_congestion_ops`:

| Callback                      | Evento do kernel                     | Descrição                                                       |
|-------------------------------|--------------------------------------|-----------------------------------------------------------------|
| `bpf_cubic_init`              | Nova conexão TCP                     | Inicializa o estado e HyStart                                   |
| `bpf_cubic_cong_avoid`        | ACK recebido (fora de loss)          | Executa slow start ou CUBIC update; chama `tcp_cong_avoid_ai`  |
| `bpf_cubic_recalc_ssthresh`   | Evento de perda detectado            | Recalcula `ssthresh`; aplica fast convergence                   |
| `bpf_cubic_state`             | Mudança de estado TCP (ex: Loss)     | Lógica customizada de reset com condição dupla (ver seção 8)    |
| `bpf_cubic_cwnd_event`        | Evento `CA_EVENT_TX_START`           | Compensa idle time ajustando `epoch_start`                      |
| `bpf_cubic_acked`             | ACK com amostra de RTT válida        | Atualiza `delay_min`; dispara HyStart se aplicável              |
| `bpf_cubic_undo_cwnd`         | Desfazimento de redução de cwnd      | Delega para `tcp_reno_undo_cwnd` via kfunc                      |

**Registro final:**

```c
SEC(".struct_ops")
struct tcp_congestion_ops cubic = {
    .init        = (void *)bpf_cubic_init,
    .ssthresh    = (void *)bpf_cubic_recalc_ssthresh,
    .cong_avoid  = (void *)bpf_cubic_cong_avoid,
    .set_state   = (void *)bpf_cubic_state,
    .undo_cwnd   = (void *)bpf_cubic_undo_cwnd,
    .cwnd_event  = (void *)bpf_cubic_cwnd_event,
    .pkts_acked  = (void *)bpf_cubic_acked,
    .name        = "bpf_cubic",
};
```

---

## 6. Fluxo do algoritmo CUBIC

```
Nova conexão
     │
     ▼
bpf_cubic_init()
  └─ bictcp_reset()        ← zera estado
  └─ bictcp_hystart_reset() ← inicia HyStart

     │
     ▼ (ACK recebido)
bpf_cubic_acked()
  └─ atualiza delay_min
  └─ hystart_update()      ← detecta saída do slow start

     │
     ▼
bpf_cubic_cong_avoid()
  ├─ [slow start] tcp_slow_start()   ← crescimento exponencial
  └─ [cong. avoid] bictcp_update()   ← crescimento cúbico
       └─ cubic_root()               ← calcula bic_K
       └─ [tcp_friendliness] cubic_beta_scale() ← fairness com Reno
     └─ tcp_cong_avoid_ai()          ← aplica incremento ao cwnd

     │
     ▼ (perda detectada)
bpf_cubic_recalc_ssthresh()
  └─ fast_convergence: reduz last_max_cwnd
  └─ retorna cwnd * beta / 1024

     │
     ▼
bpf_cubic_state(TCP_CA_Loss)
  └─ [se Loss AND curr_rtt >= delay_min * mult_rtt]
       └─ bictcp_reset()
       └─ bictcp_hystart_reset()
```

---

## 7. Configuração dinâmica via mapa eBPF

Os parâmetros do CUBIC podem ser alterados **sem recarregar o programa**, com efeito imediato nas próximas chamadas.

### Localizar o ID do mapa

```bash
sudo bpftool map show | grep cubic_cfg
# Exemplo: 123: array  name cubic_cfg  flags 0x0
```

### Ler os valores atuais

```bash
sudo bpftool map dump id 123
```

### Escrever novos valores

Os valores são escritos como **12 bytes em little-endian** (`beta` + `bic_scale` + `mult_rtt`, 4 bytes cada):

```bash
# Exemplo: beta=800, bic_scale=50, mult_rtt=5
sudo bpftool map update id 123 \
  key hex 00 00 00 00 \
  value hex 20 03 00 00 32 00 00 00 05 00 00 00
```

#### Tabela de conversão rápida

| Campo       | Decimal | Hex (little-endian) |
|-------------|---------|----------------------|
| `beta` = 717 (default) | `717` | `cd 02 00 00` |
| `beta` = 800 (agressivo) | `800` | `20 03 00 00` |
| `beta` = 650 (conservador) | `650` | `8a 02 00 00` |
| `bic_scale` = 41 (default) | `41` | `29 00 00 00` |
| `bic_scale` = 50 (agressivo) | `50` | `32 00 00 00` |
| `bic_scale` = 30 (conservador) | `30` | `1e 00 00 00` |
| `mult_rtt` = 5 (default) | `5` | `05 00 00 00` |
| `mult_rtt` = 8 (conservador) | `8` | `08 00 00 00` |

### Restaurar defaults

```bash
sudo bpftool map update id 123 \
  key hex 00 00 00 00 \
  value hex 00 00 00 00 00 00 00 00 00 00 00 00
```

> Ao zerar o mapa, todas as funções de leitura retornam automaticamente os valores `#define`.

---

## 8. Lógica customizada de reset em `bpf_cubic_state`

Esta é a principal **divergência comportamental** desta implementação em relação ao CUBIC padrão do kernel.

No `tcp_cubic.c` original, qualquer evento `TCP_CA_Loss` dispara o reset do estado. Nesta implementação, o reset **só ocorre se duas condições forem verdadeiras simultaneamente**:

```c
__u8 is_loss_state = (new_state == TCP_CA_Loss);
__u8 is_rtt_x = (ca->curr_rtt >= ca->delay_min * mult_rtt);

if (is_loss_state && is_rtt_x) {
    bictcp_reset(ca);
    bictcp_hystart_reset(sk);
}
```

| Condição      | Descrição                                               |
|---------------|---------------------------------------------------------|
| `is_loss_state` | O kernel sinalizou estado de perda (`TCP_CA_Loss`)   |
| `is_rtt_x`    | O RTT atual é ≥ `mult_rtt` × RTT mínimo histórico      |

**Efeito prático:** perdas em condições de RTT estável (ex: perda aleatória em redes sem congestionamento real) **não disparam reset completo** do algoritmo. Apenas perdas acompanhadas de aumento significativo de RTT — indicativo de congestionamento genuíno — causam reset.

O valor de `mult_rtt` (default `5`) é controlável via mapa eBPF em tempo real.

---

## 9. Diferenças em relação ao `tcp_cubic.c` do kernel

| Aspecto                        | `tcp_cubic.c` (kernel)              | `bpf_cubic.c` (este arquivo)                        |
|--------------------------------|--------------------------------------|-----------------------------------------------------|
| Parâmetros `beta`, `bic_scale` | Constantes ou parâmetros de módulo  | Mutáveis em tempo real via mapa eBPF               |
| Unidade de tempo em `bictcp_update` | Jiffies (usa `usecs_to_jiffies`) | Microssegundos diretos (`USEC_PER_JIFFY`)           |
| Loop `while` em tcp_friendliness | `while (ca->ack_cnt > delta)`     | Substituído por divisão inteira `ca->ack_cnt / delta` |
| Reset em `TCP_CA_Loss`         | Sempre reseta                        | Reseta apenas se Loss **E** RTT ≥ `mult_rtt × delay_min` |
| Parâmetro `mult_rtt`           | Não existe                           | Novo parâmetro exclusivo desta implementação        |
| `CONFIG_HZ`                    | Macro do kernel                      | Obtido via `.kconfig` map do eBPF                   |

---

## 10. Remoção do algoritmo

```bash
# Desregistrar o CCA
sudo bpftool struct_ops unregister name cubic

# Confirmar remoção
bpftool struct_ops show

# Restaurar o algoritmo padrão do sistema (ex: cubic nativo)
sudo sysctl -w net.ipv4.tcp_congestion_control=cubic
```

---

## 11. Notas e observações

- **`bpf_cubic_acked_called`** — variável global `int bpf_cubic_acked_called = 0` usada como flag de debug para confirmar que `bpf_cubic_acked` está sendo invocado. Não afeta o comportamento do algoritmo.

- **Código comentado em `bpf_cubic_state`** — o arquivo contém duas versões alternativas de `bpf_cubic_state` comentadas. Uma inclui cálculo de `rtt_metrics`; outra é o comportamento padrão do kernel (reset incondicional em Loss). A versão ativa é a de **reset condicional duplo**.

- **Includes duplicados** — `bpf_helpers.h`, `bpf_core_read.h` e `bpf_tracing.h` aparecem incluídos duas vezes cada. Não causam erro de compilação com clang, mas podem ser limpos.

- **`bic_scale` tem clamp no código, não no mapa** — valores fora de `[10, 60]` escritos no mapa são silenciosamente corrigidos pela função `cubic_bic_scale()`. Não há validação na escrita.

- **Funções de métricas de RTT não são chamadas ativamente** — o bloco `calculate_rtt_metrics()`, `get_rtt_stats()` etc. está implementado mas não integrado ao fluxo principal. Foram projetadas para uso futuro em monitoramento ou em versões de `bpf_cubic_state` que estão comentadas.

- **Desligar interface gráfica** — o comentário `sudo systemctl stop gdm` no cabeçalho do arquivo sugere que o ambiente de testes usa uma VM ou máquina com GPU. Isso não é necessário para o funcionamento do programa.
