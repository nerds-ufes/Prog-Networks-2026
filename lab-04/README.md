# TCP Metrics via eBPF SockOps

Ferramenta de monitoramento de métricas TCP em tempo real usando um programa eBPF do tipo `sockops`, fixado no cgroup v2 do sistema. Coleta informações por fluxo (cwnd, RTT, retransmissões, bytes confirmados) diretamente no kernel, sem instrumentação da aplicação.

---

## Arquivos

| Arquivo | Descrição |
|---|---|
| `tcp_sockops_metrics.c` | Programa eBPF em C — coleta métricas por fluxo TCP |
| `load.sh` | Compila, carrega e anexa o programa ao cgroup |
| `unload.sh` | Desanexa e remove o programa; limpa arquivos temporários |
| `tcp_metrics_reader.py` | Lê o mapa eBPF pinado e exibe as métricas em tempo real |

---

## Pré-requisitos

```bash
# Ferramentas de compilação e BPF
sudo apt install clang-18 linux-tools-$(uname -r) bpftool

# Biblioteca Python para leitura do mapa
sudo apt install python3-bpfcc        # Ubuntu/Debian
# ou
sudo dnf install python3-bcc          # Fedora/RHEL
```

> O sistema deve usar **cgroup v2**. Verifique com: `mount | grep cgroup2`

---

## Fluxo de execução

```
tcp_sockops_metrics.c
        │
        │  clang-18 (compilação BPF)
        ▼
tcp_sockops_metrics.o
        │
        │  bpftool prog load  → pina em /sys/fs/bpf/tcp_sockops
        │  bpftool cgroup attach /sys/fs/cgroup (sock_ops, multi)
        ▼
  Kernel: evento BPF_SOCK_OPS_*
        │  callbacks: RTT_CB, RTO_CB, RETRANS_CB, STATE_CB
        ▼
  mapa BPF tcp_flows (hash, 16 384 entradas)
  pinado em /sys/fs/bpf/tcp_flows
        │
        │  tcp_metrics_reader.py (leitura periódica via libbcc)
        ▼
  Tabela no terminal (ou JSON)
```

---

## Uso rápido

### 1. Gerar o header do kernel (uma vez por boot/versão)

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

### 2. Carregar o programa eBPF

```bash
sudo ./load.sh
```

O script executa:
1. Compila `tcp_sockops_metrics.c` → `tcp_sockops_metrics.o` com `clang-18`
2. Remove pins antigos em `/sys/fs/bpf/tcp_sockops` e `/sys/fs/bpf/tcp_flows`
3. Carrega o objeto BPF e pina em `/sys/fs/bpf/tcp_sockops`
4. Anexa ao cgroup raiz (`/sys/fs/cgroup`) no hook `sock_ops` com flag `multi`

### 3. Monitorar métricas

```bash
# Visualização padrão (atualiza a cada 1 s, exibe até 15 fluxos, ordenado por RTT)
sudo python3 tcp_metrics_reader.py

# Atualizar a cada 2 s, exibir até 20 fluxos
sudo python3 tcp_metrics_reader.py --interval 2 --top 20

# Filtrar por IP de origem ou destino
sudo python3 tcp_metrics_reader.py --filter-ip 192.168.1.100

# Ordenar por cwnd (útil para acompanhar slow-start/congestion avoidance)
sudo python3 tcp_metrics_reader.py --sort cwnd

# Saída em JSON (uma linha por ciclo, adequado para pipelines)
sudo python3 tcp_metrics_reader.py --json
```

**Opções de ordenação (`--sort`):**

| Valor | Campo ordenado |
|---|---|
| `srtt` (padrão) | RTT suavizado (µs) |
| `cwnd` | Janela de congestionamento atual |
| `retrans` | Número de retransmissões |
| `bytes` | Bytes confirmados (bytes_acked) |

### 4. Gerar tráfego de teste

```bash
# Em outra janela — transferência de 60 s para observar o crescimento do cwnd
iperf3 -c <IP_DESTINO> -t 60 -i 1 &
sudo python3 tcp_metrics_reader.py --sort cwnd
```

### 5. Remover o programa

```bash
# Remoção interativa com confirmação
sudo ./unload.sh

# Forçar remoção sem confirmação
sudo ./unload.sh --force

# Apenas verificar o status atual sem alterar nada
sudo ./unload.sh --status

# Remover mas manter os arquivos .o e vmlinux.h
sudo ./unload.sh --keep-files
```

---

## Métricas coletadas

| Coluna | Campo BPF | Descrição |
|---|---|---|
| `RTT(µs)` | `srtt_us` | RTT suavizado em microssegundos (`srtt_us >> 3` do kernel) |
| `CWND` | `snd_cwnd` | Janela de congestionamento atual (segmentos) |
| `CWND_MAX` | — | Pico histórico de `cwnd` na conexão |
| `IN_FLIGHT` | `packets_out` | Segmentos em voo no momento do `RTT_CB` |
| `SSTHRESH` | `snd_ssthresh` | Limiar de slow-start (`∞` quando ≥ 0xFFFF) |
| `BYTES_ACK` | `bytes_acked` | Total de bytes confirmados pelo receptor |
| `RETRANS` | — | Retransmissões contadas via `RETRANS_CB` + estimativa indireta |
| `IDADE` | `timestamp_ns` | Tempo desde a última atualização da entrada no mapa |

**Destaques visuais:**
- RTT > 100 ms — amarelo
- Retransmissões > 0 — vermelho
- `cwnd` igual ao pico histórico e > 10 — verde (fase de crescimento)

---

## Detalhes do programa eBPF (`tcp_sockops_metrics.c`)

### Callbacks ativados por conexão

Ao detectar `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` ou `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`, o programa habilita os callbacks:

```
BPF_SOCK_OPS_RTT_CB_FLAG     — dispara a cada RTT estimado
BPF_SOCK_OPS_STATE_CB_FLAG   — dispara em mudanças de estado TCP
BPF_SOCK_OPS_RETRANS_CB_FLAG — dispara em cada retransmissão
BPF_SOCK_OPS_RTO_CB_FLAG     — dispara em timeout de retransmissão (RTO)
```

### Mapa BPF

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key,   struct tcp_flow_key);   // src/dst IP+porta+família
    __type(value, struct tcp_flow_stats); // métricas por fluxo
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_flows SEC(".maps");
```

O mapa é pinado automaticamente em `/sys/fs/bpf/tcp_flows` pelo `libbpf` (campo `pinning`).

### Limpeza automática de entradas

Quando o estado TCP transita para `TCP_CLOSE` ou `TCP_CLOSE_WAIT`, a entrada correspondente é removida do mapa, evitando esgotamento das 16 384 entradas em produção.

### Suporte a IPv4 e IPv6

A chave do mapa usa `union` para armazenar endereços IPv4 (32 bits) ou IPv6 (128 bits). A família é registrada no campo `family` (`AF_INET = 2` / `AF_INET6 = 10`).

---

## Detalhes do script `unload.sh`

O script aceita os seguintes argumentos:

```
Uso: sudo ./unload.sh [OPÇÕES]

  -h, --help        Mostra a ajuda
  -f, --force       Força a limpeza sem confirmação interativa
  -s, --status      Exibe o status atual dos recursos BPF sem alterações
  -k, --keep-files  Mantém os arquivos temporários (.o e vmlinux.h)
```

A limpeza completa executa, nesta ordem:
1. Desanexa o programa do cgroup (`bpftool cgroup detach`)
2. Remove o pin do programa (`rm /sys/fs/bpf/tcp_sockops_metrics`)
3. Remove os arquivos temporários `tcp_sockops_metrics.o` e `vmlinux.h`
4. Verifica se há outros programas BPF com nome similar carregados

---

## Estrutura dos diretórios relevantes

```
/sys/fs/bpf/
├── tcp_sockops           ← programa eBPF pinado (criado por load.sh)
└── tcp_flows             ← mapa hash pinado (criado automaticamente pelo libbpf)

/sys/fs/cgroup/           ← cgroup v2 raiz (ponto de attach do hook sock_ops)
```

---

## Referências

- [BPF sockops — kernel docs](https://www.kernel.org/doc/html/latest/bpf/prog_sockops.html)
- [bpftool man page](https://man7.org/linux/man-pages/man8/bpftool.8.html)
- [libbpf CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/)
- [BCC Python bindings](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)

