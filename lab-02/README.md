# lab-04 — Topologia Containerlab para Testes de TCP com eBPF

Laboratório containerlab para análise de comportamento do TCP sob condições de rede degradadas. A topologia simula um ambiente com delay, perda de pacotes e limitação de banda no link de backbone, ideal para validar implementações de controle de congestionamento via eBPF (ex: `bpf_cubic`).

---

## Sumário

1. [Visão geral da topologia](#1-visão-geral-da-topologia)
2. [Pré-requisitos](#2-pré-requisitos)
3. [Nós da topologia](#3-nós-da-topologia)
   - [Hosts (PC1, PC2, PC3)](#hosts-pc1-pc2-pc3)
   - [SW1 — Switch com emulação de rede](#sw1--switch-com-emulação-de-rede)
   - [SW2 — Switch simples](#sw2--switch-simples)
4. [Links e conectividade](#4-links-e-conectividade)
5. [Emulação de rede (netem + tbf)](#5-emulação-de-rede-netem--tbf)
6. [Endereçamento IP](#6-endereçamento-ip)
7. [Binds do sistema host](#7-binds-do-sistema-host)
8. [Executando o laboratório](#8-executando-o-laboratório)
9. [Casos de uso e testes sugeridos](#9-casos-de-uso-e-testes-sugeridos)
10. [Notas e observações](#10-notas-e-observações)

---

## 1. Visão geral da topologia

```
                        ┌─────────────────────────────────────┐
                        │     Backbone com degradação de rede  │
                        │   delay 50ms | loss 1% | 10 Mbit/s  │
                        └─────────────────────────────────────┘
                                          │
  PC1 ──[eth1]──► SW1:eth1               │
  PC3 ──[eth1]──► SW1:eth3    SW1:eth2 ──┘──► SW2:eth1 ──[eth2]──► PC2
                  └─── br0 ───┘                └─── br0 ───┘
```

O **link entre SW1 e SW2** é o gargalo intencional do laboratório, com emulação de rede configurada via `tc`. Todos os fluxos entre os hosts PCs passam obrigatoriamente por esse link.

---

## 2. Pré-requisitos

### Software

| Ferramenta      | Versão mínima | Observação                        |
|-----------------|---------------|-----------------------------------|
| `containerlab`  | ≥ 0.48        | Orquestrador do laboratório       |
| Docker          | ≥ 24.0        | Runtime dos containers            |
| `iproute2`      | —             | Para `tc`, `ip` dentro dos nós    |

### Imagem Docker

Todos os nós utilizam a imagem `ebpf-host:latest`. Essa imagem deve conter:

- `clang` / `llvm`
- `libbpf`
- `bpftool`
- `iproute2` (com suporte a `tc netem` e `tbf`)
- Headers do kernel

> ⚠️ A imagem deve ser construída localmente antes de iniciar o lab. Certifique-se de que ela está disponível no Docker do host:
>
> ```bash
> docker images | grep ebpf-host
> ```

### Módulos do kernel no host

Os binds de `/lib/modules` e `/boot` exigem que o host tenha os módulos do kernel compatíveis com a versão em execução nos containers.

---

## 3. Nós da topologia

### Hosts (PC1, PC2, PC3)

Três hosts Linux que atuam como endpoints de tráfego TCP.

| Nó  | Interface | MAC               | IP           |
|-----|-----------|-------------------|--------------|
| PC1 | `eth1`    | `00:00:00:00:01:01` | `10.0.0.1/24` |
| PC2 | `eth1`    | `00:00:00:00:02:02` | `10.0.0.2/24` |
| PC3 | `eth1`    | `00:00:00:00:03:03` | `10.0.0.3/24` |

**Configuração aplicada automaticamente no boot de cada host:**

```bash
ip link set dev eth1 address <MAC>
ip addr add <IP>/24 dev eth1
ip link set eth1 up
```

**Binds do host (para uso de eBPF):**

```yaml
binds:
  - /sys/fs/bpf:/sys/fs/bpf       # Filesystem BPF pinning
  - /lib/modules:/lib/modules     # Módulos do kernel
  - /usr/sbin/bpftool:/usr/sbin/bpftool  # Ferramenta bpftool
  - /boot:/boot                   # Headers e config do kernel (apenas PC1)
```

> ℹ️ O bind de `/boot` está presente apenas em **PC1**. PC2 e PC3 não o possuem.

---

### SW1 — Switch com emulação de rede

Atua como switch Linux nativo via bridge (`br0`), conectando três interfaces. É o nó central da topologia e o ponto onde a degradação de rede é aplicada.

**Configuração da bridge:**

```bash
ip link add br0 type bridge
ip link set br0 up
ip link set eth1 master br0
ip link set eth2 master br0
ip link set eth3 master br0
ip link set eth1 up
ip link set eth2 up
ip link set eth3 up
```

**Emulação de rede aplicada em `eth2` (link de uplink para SW2):**

```bash
# Adiciona delay de 50ms e 1% de perda de pacotes
tc qdisc add dev eth2 root netem delay 50ms loss 1%

# Limita a banda a 10 Mbit/s com burst de 32kbit e latência máxima de 400ms
tc qdisc add dev eth2 parent 1:1 tbf rate 10mbit burst 32kbit latency 400ms
```

> ⚠️ A emulação está configurada apenas na direção de **saída** de `eth2` (SW1 → SW2). Para emulação bidirecional, é necessário aplicar `tc` também em `eth1` de SW2.

---

### SW2 — Switch simples

Bridge Linux simples, sem emulação de rede, conectando o backbone (vindo de SW1) ao host PC2.

**Configuração da bridge:**

```bash
ip link add br0 type bridge
ip link set br0 up
ip link set eth1 master br0
ip link set eth2 master br0
ip link set eth1 up
ip link set eth2 up
```

---

## 4. Links e conectividade

```yaml
links:
  - endpoints: ["PC1:eth1", "SW1:eth1"]   # PC1 conectado ao SW1
  - endpoints: ["PC3:eth1", "SW1:eth3"]   # PC3 conectado ao SW1
  - endpoints: ["SW1:eth2", "SW2:eth1"]   # Backbone (com degradação)
  - endpoints: ["SW2:eth2", "PC2:eth1"]   # PC2 conectado ao SW2
```

### Diagrama de interfaces

```
PC1:eth1  ───────────────►  SW1:eth1
                             SW1 (br0)
PC3:eth1  ───────────────►  SW1:eth3
                             SW1:eth2  ──[netem+tbf]──►  SW2:eth1
                                                          SW2 (br0)
                                                          SW2:eth2  ──►  PC2:eth1
```

---

## 5. Emulação de rede (netem + tbf)

A degradação de rede é aplicada no link `SW1:eth2 → SW2:eth1` usando dois qdiscs encadeados:

### `netem` — Network Emulator

| Parâmetro | Valor  | Efeito                                  |
|-----------|--------|-----------------------------------------|
| `delay`   | 50 ms  | Adiciona latência extra a cada pacote   |
| `loss`    | 1%     | Descarta aleatoriamente 1% dos pacotes  |

### `tbf` — Token Bucket Filter

| Parâmetro | Valor    | Efeito                                        |
|-----------|----------|-----------------------------------------------|
| `rate`    | 10 Mbit/s | Banda máxima permitida no link               |
| `burst`   | 32 kbit  | Tamanho máximo do burst instantâneo           |
| `latency` | 400 ms   | Tempo máximo que um pacote pode aguardar na fila |

> **Objetivo:** Simular um link WAN realista, adequado para observar o comportamento de algoritmos de controle de congestionamento TCP (como o `bpf_cubic`) sob pressão.

---

## 6. Endereçamento IP

Todos os hosts estão na mesma sub-rede e se comunicam diretamente via L2 (bridge):

| Host | Endereço IP   | Gateway |
|------|---------------|---------|
| PC1  | `10.0.0.1/24` | —       |
| PC2  | `10.0.0.2/24` | —       |
| PC3  | `10.0.0.3/24` | —       |

> ℹ️ Não há roteamento configurado. A comunicação entre os hosts é inteiramente via switching L2.

---

## 7. Binds do sistema host

Os hosts PC1, PC2 e PC3 montam recursos do sistema host para permitir o uso de eBPF dentro dos containers:

| Bind                                      | Finalidade                                      |
|-------------------------------------------|-------------------------------------------------|
| `/sys/fs/bpf:/sys/fs/bpf`                | Permite pinning de mapas e programas eBPF       |
| `/lib/modules:/lib/modules`              | Acesso aos módulos do kernel do host            |
| `/usr/sbin/bpftool:/usr/sbin/bpftool`   | Disponibiliza o `bpftool` dentro do container   |
| `/boot:/boot`                             | Acesso a headers e configuração do kernel (PC1) |

> ⚠️ As capabilities `NET_ADMIN`, `SYS_ADMIN` e `SYS_RESOURCE` estão **comentadas** no arquivo. Para uso completo de eBPF (carregamento de programas, criação de mapas), pode ser necessário descomentar esse bloco em cada nó:
>
> ```yaml
> capabilities:
>   - NET_ADMIN
>   - SYS_ADMIN
>   - SYS_RESOURCE
> ```

---

## 8. Executando o laboratório

### Iniciar o lab

```bash
sudo containerlab deploy -t topology-04.yml
```

### Verificar os nós

```bash
sudo containerlab inspect -t topology-04.yml
```

### Acessar um nó

```bash
docker exec -it clab-lab-04-PC1 bash
docker exec -it clab-lab-04-SW1 bash
```

### Encerrar o lab

```bash
sudo containerlab destroy -t topology-04.yml
```

---

## 9. Casos de uso e testes sugeridos

### Teste de conectividade básica

```bash
# De PC1, pingar PC2 e PC3
docker exec -it clab-lab-04-PC1 ping 10.0.0.2
docker exec -it clab-lab-04-PC1 ping 10.0.0.3
```

### Validação da emulação de rede

```bash
# Verificar latência no caminho PC1 → PC2 (deve refletir os 50ms)
docker exec -it clab-lab-04-PC1 ping -c 20 10.0.0.2
```

### Teste de throughput com `iperf3`

```bash
# No PC2 (servidor)
docker exec -it clab-lab-04-PC2 iperf3 -s

# No PC1 (cliente)
docker exec -it clab-lab-04-PC1 iperf3 -c 10.0.0.2 -t 30
```

> O throughput deve ser limitado a ~10 Mbit/s pelo `tbf` em SW1.

### Inspeção de conexões TCP

```bash
docker exec -it clab-lab-04-PC1 ss -ti
```

Métricas úteis: `cwnd`, `rtt`, `retrans`, `pacing_rate`.

### Verificar qdiscs aplicados no SW1

```bash
docker exec -it clab-lab-04-SW1 tc qdisc show dev eth2
```

---

## 10. Notas e observações

- **Emulação unidirecional:** O `netem` e o `tbf` estão aplicados apenas em `SW1:eth2` (direção SW1 → SW2). O tráfego de retorno (SW2 → SW1) não sofre degradação adicional.

- **Capabilities comentadas:** Para carregar programas eBPF dentro dos containers, descomente o bloco `capabilities` nos nós desejados.

- **MACs fixos:** Os endereços MAC dos hosts são configurados manualmente para garantir reprodutibilidade entre execuções do lab.

- **Hierarquia de qdiscs:** O `tbf` está configurado como filho (`parent 1:1`) do `netem`. Para que a hierarquia funcione corretamente, o `netem` deve criar um handle `1:` automaticamente. Caso ocorram erros, considere especificar o handle explicitamente:

  ```bash
  tc qdisc add dev eth2 root handle 1: netem delay 50ms loss 1%
  tc qdisc add dev eth2 parent 1:1 handle 10: tbf rate 10mbit burst 32kbit latency 400ms
  ```

- **Sem bind de `/boot` em PC2 e PC3:** Caso precise compilar programas eBPF nesses nós, adicione o bind manualmente no arquivo de topologia.
