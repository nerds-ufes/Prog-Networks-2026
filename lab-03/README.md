# 🐝 Laboratório XDP/eBPF com Containerlab — Contagem de Pacotes em Tempo Real

> Laboratório prático de **contagem de pacotes em velocidade de linha** usando **eBPF/XDP** em um ambiente de rede virtualizado com **Containerlab**.

[![Containerlab](https://img.shields.io/badge/Containerlab-v0.50+-blue?logo=linux)](https://containerlab.dev)
[![Docker](https://img.shields.io/badge/Docker-required-blue?logo=docker)](https://www.docker.com)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange)](https://ebpf.io)
[![Licença](https://img.shields.io/badge/licença-GPL--2.0-green)](LICENSE)

---

## Visão Geral

Este laboratório demonstra um recurso muito poderoso do kernel Linux: o **XDP (eXpress Data Path)**. Aqui é anexado um pequeno programa eBPF na interface de rede, que **conta pacotes antes mesmo que eles cheguem à pilha de rede**, tornando a contagem praticamente "gratuita" em termos de CPU.

A grande diferença em relação ao laboratório anterior (`1_pkt_drop`) é que aqui temos **um programa C rodando no userspace** (`counter.c`) que carrega o programa XDP no kernel, lê o BPF Map a cada segundo e exibe estatísticas em tempo real — sem precisar do `bpftool`.

**O que este laboratório demonstra:**
- Compilação de um programa eBPF em C para bytecode BPF usando Docker como ambiente de build.
- Compilação de um loader C (`counter.c`) que roda no **userspace** usando Docker.
- Deploy de uma rede virtual com 2 nós usando Containerlab.
- Carregamento e anexo de um programa XDP via **libbpf** (no próprio loader C).
- Contagem de pacotes em velocidade de linha com leitura automática do **BPF Map**.
- O laboratório usa `iperf3` para gerar tráfego UDP e validar a contagem.

---

## Topologia

```
┌─────────────────────────────────────────┐
│               Máquina Host              │
│                                         │
│  ┌──────────┐ eth1   eth1 ┌──────────┐  │
│  │  node-a  ├─────────────┤  node-b  │  │
│  │10.0.0.1  │             │10.0.0.2  │  │
│  └──────────┘             └──────────┘  │
│    (emissor)            (contador XDP)  │
└─────────────────────────────────────────┘
```

- **node-a**: Máquina Linux usando a imagem `nicolaka/netshoot` — gera tráfego UDP com `iperf3`.
- **node-b**: Máquina Linux `nicolaka/netshoot` com bind montando `counter.bpf.o` do host em `/counter.bpf.o` — executa o loader `counter` que anexa o XDP e lê o contador.

| Nó     | Endereço IP  | Função                                          |
|--------|-------------|-------------------------------------------------|
| node-a | `10.0.0.1`  | Emissor de pacotes (origem do tráfego UDP)      |
| node-b | `10.0.0.2`  | Contador XDP — conta pacotes com eBPF + libbpf  |

---

## Pré-requisitos

### 0. Requisitos do Sistema

Os seguintes requisitos devem ser atendidos para que a ferramenta containerlab seja executada com sucesso (https://containerlab.dev/install/):

- Um usuário com privilégios de `sudo` para executar o containerlab.
- Um servidor Linux (Ubuntu 20.04+), pode ser WSL2 (https://learn.microsoft.com/pt-br/windows/wsl/install).
- Kernel Linux ≥ 5.4 (recomendado 5.15+).
- Total de espaço em disco recomendado: ~2 GB livres para rodar confortavelmente (inclui espaço para logs, cache e futuras imagens).


### 1. Instalar o Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

> Saia e entre novamente na sessão após adicionar seu usuário ao grupo `docker`.

### 2. Instalar o Containerlab

```bash
bash -c "$(curl -sL https://get.containerlab.dev)"
```

Verifique a instalação:

```bash
containerlab version
```

---

## Obtendo o Laboratório

Clone o repositório e acesse o diretório do laboratório:

```bash
git clone https://github.com/DANIELVENTORIM/ebpf-lab.git
cd ebpf-lab/2_pkt_counter
```

> Arquivos principais:
> - `ebpf-counter.clab.yml` — Definição da topologia Containerlab
> - `counter.bpf.c` — Código-fonte eBPF/XDP (roda no kernel)
> - `counter.c` — Loader userspace (carrega e lê o contador)
> - `compile.sh` — Script de compilação do programa eBPF via Docker
> - `compile_us.sh` — Script de compilação do loader C via Docker

---

## Passo 1 — Compilar os Programas

Este laboratório tem **dois** programas para compilar:
1. **`counter.bpf.c`** → bytecode BPF que roda no kernel (via `clang -target bpf`)
2. **`counter.c`** → programa C que roda no userspace (via `gcc -lbpf`)

Ambos usam um **container Docker como ambiente de build**, dispensando a instalação de toolchain no host.

### 1.1 Compilar o Programa eBPF (Kernel Side)

```bash
./compile.sh
```

<details>
<summary>O que o compile.sh faz?</summary>

Ele sobe um container Docker temporário que:
1. Instala `clang`, `llvm`, `libbpf-dev` e `gcc-multilib`.
2. Compila `counter.bpf.c` gerando bytecode para a **máquina virtual BPF** (`-target bpf`).
3. Gera o arquivo objeto `counter.bpf.o` no diretório atual.
4. Remove o container de build automaticamente (`--rm`).

</details>

**Saída esperada:**
```
Success! counter.bpf.o created.🍻🍻🍻
```

### 1.2 Verificar o Bytecode Gerado

```bash
file counter.bpf.o
```

**Saída esperada:**
```
counter.bpf.o: ELF 64-bit LSB relocatable, eBPF, version 1 (SYSV), not stripped
```

### 1.3 Compilar o Loader Userspace

```bash
./compile_us.sh
```

<details>
<summary>O que o compile_us.sh faz?</summary>

Ele sobe um container Ubuntu 24.04 que:
1. Instala `gcc`, `libbpf-dev`, `libelf-dev` e `zlib1g-dev`.
2. Compila `counter.c` linkando contra `libbpf`, `libelf` e `zlib`.
3. Gera o executável `counter` no diretório atual.
4. Remove o container de build automaticamente.

</details>

**Saída esperada:**
```
Sucess! loader counter created.🍻🍻🍻
```

### 1.4 Verificar o Executável

```bash
ls -lh counter counter.bpf.o
```

**Saída esperada:**
```
-rwxr-xr-x 1 daniel daniel  17K Apr  7 10:00 counter
-rw-r--r-- 1 daniel daniel 6.2K Apr  7 10:00 counter.bpf.o
```

---

## Passo 2 — Deploy da Topologia

```bash
sudo containerlab deploy -t ebpf-counter.clab.yml --reconfigure
```

Isso irá:
- Criar dois containers Linux (`node-a` e `node-b`) com a imagem `nicolaka/netshoot`.
- Configurar os IPs nas interfaces `eth1` de cada nó (`10.0.0.1` e `10.0.0.2`).
- Montar o `counter.bpf.o` dentro do `node-b` em `/counter.bpf.o`.
- Instalar `libbpf` e `bpftool` automaticamente no `node-b`.
- Criar um link virtual direto entre as interfaces `eth1` dos dois nós.

**Saída esperada:**
```
INFO[0000] Parsing & executing definition file: ebpf-counter.clab.yml
INFO[0000] Creating docker network 'clab'
INFO[0000] Creating container 'node-a'
INFO[0000] Creating container 'node-b'
INFO[0000] Creating virtual wire: node-a:eth1 <--> node-b:eth1
INFO[0001] New containers have been created

╭──────────────────────────┬──────────────────────────┬─────────┬───────────────────╮
│           Name           │        Kind/Image        │  State  │   IPv4/6 Address  │
├──────────────────────────┼──────────────────────────┼─────────┼───────────────────┤
│ clab-ebpf-counter-node-a │ linux                    │ running │ 172.20.20.2       │
│                          │ nicolaka/netshoot:latest │         │                   │
├──────────────────────────┼──────────────────────────┼─────────┼───────────────────┤
│ clab-ebpf-counter-node-b │ linux                    │ running │ 172.20.20.3       │
│                          │ nicolaka/netshoot:latest │         │                   │
╰──────────────────────────┴──────────────────────────┴─────────┴───────────────────╯
```

---

## 🐝 Passo 3 — Verificar Conectividade Inicial

Antes de ativar o contador XDP, confirme que os nós se comunicam normalmente:

```bash
sudo docker exec clab-ebpf-counter-node-a ping -c 3 10.0.0.2
```

**Resultado esperado:** `0% packet loss`

---

## 🐝 Passo 4 — Ativar o Contador XDP

### 4.1 Copiar o Loader para node-b

O executável `counter` foi compilado no host. Precisamos copiá-lo para dentro do container:

```bash
sudo docker cp counter clab-ebpf-counter-node-b:/counter
```

### 4.2 Rodar o Contador em node-b

**Abra um terminal** e execute o loader dentro do `node-b`:

```bash
sudo docker exec -it clab-ebpf-counter-node-b /counter eth1
```

O que acontece por dentro:
1. `counter` encontra o arquivo `/counter.bpf.o` (montado via bind pelo Containerlab)
2. Abre e carrega o bytecode BPF no kernel via `bpf_object__open` + `bpf_object__load`
3. Obtém o programa `xdp_packet_counter` e o anexa à interface `eth1` via `bpf_xdp_attach`
4. Entra em loop: a cada segundo lê o BPF Map `packet_counter` e mostra as estatísticas

**Saída esperada:**

```
╔════════════════════════════════════════════════╗
║  eBPF Packet Counter - XDP Loader              ║
╚════════════════════════════════════════════════╝

[✓] Interface: eth1 (index: 11)
[✓] Encontrado: /counter.bpf.o
[*] Carregando programa...
[✓] Programa carregado
[*] Anexando ao XDP...
[✓] Anexado com sucesso

╔════════════════════════════════════════════════╗
║  XDP Packet Counter Rodando                    ║
║  Interface: eth1                               ║
║  Pressione Ctrl+C para sair                    ║
╚════════════════════════════════════════════════╝

[  1] Total:            0 | Taxa:          0 pps
[  2] Total:            0 | Taxa:          0 pps
```

> **⚠️ IMPORTANTE:** Deixe este terminal **ABERTO** enquanto faz os testes no Passo 5!

---

## Passo 5 — Verificar Contagem de Pacotes

Abra um **NOVO TERMINAL** enquanto deixa o contador rodando no primeiro.

### 5.1 Teste com Ping (Rápido)

```bash
sudo docker exec clab-ebpf-counter-node-a ping -c 10 10.0.0.2
```

Volte ao terminal do contador e observe os valores aumentando a cada resposta.

**Resultado esperado:** `0% packet loss` (o contador **não descarta** pacotes, apenas os conta)

### 5.2 Gerar Tráfego com iperf3

Para gerar tráfego UDP contínuo e ver a taxa de pacotes por segundo:

```bash
# Ligar o servidor iperf3 em background no node-b.
sudo docker exec -d clab-ebpf-counter-node-b iperf3 -s
```

```bash
# Abrir shell interativo em node-a
sudo docker exec -it clab-ebpf-counter-node-a bash
```

**Dentro do container node-a:**

```bash
# Gerar fluxo UDP a 1 Mbps por 30 segundos
iperf3 -c 10.0.0.2 -u -b 1M -t 30
```

**Flags explicadas:**
- `-c 10.0.0.2` = conectar ao IP do node-b
- `-u` = usar UDP
- `-b 1M` = 1 Megabit por segundo
- `-t 30` = por 30 segundos

**Saída esperada em node-a:**
```
Connecting to host 10.0.0.2, port 5201
[  5] local 10.0.0.1 port 45678 connected to 10.0.0.2 port 5201
[ ID] Interval           Transfer     Bitrate         Jitter    Lost/Total Datagrams
[  5]   0.00-1.00   sec   128 KBytes  1.05 Mbits/sec  0.045 ms   0/92 (0%)
[  5]   1.00-2.00   sec   128 KBytes  1.05 Mbits/sec  0.043 ms   0/92 (0%)
...
```

### 5.3 Observar o Contador Crescendo

Volte ao **PRIMEIRO TERMINAL** onde o `counter` está rodando:

**Saída esperada:**
```
[  1] Total:            0 | Taxa:          0 pps
[  2] Total:          184 | Taxa:        184 pps
[  3] Total:          368 | Taxa:        184 pps
[  4] Total:          552 | Taxa:        184 pps
[  5] Total:          736 | Taxa:        184 pps
```

** SUCESSO:** O programa eBPF está contando os pacotes em tempo real diretamente no kernel!

> **Análise:** Com iperf3 a 1 Mbps e pacotes UDP padrão (~1400 bytes), a taxa esperada é ~89 pps. Com pacotes menores (~128 bytes), pode chegar a ~900 pps.

---

## Passo 6 — Verificação Avançada (Opcional)

### 6.1 Inspecionar o BPF Map com bpftool

Em um **NOVO TERMINAL**:

```bash
# Ver maps carregados
sudo docker exec clab-ebpf-counter-node-b bpftool map show

# Esperado:
# 3: array  name packet_counter  flags 0x0
#     key 4B  value 8B  max_entries 1  memlock 4096B

# Dump do valor atual do map
sudo docker exec clab-ebpf-counter-node-b bpftool map dump name packet_counter

# Esperado:
# [{
#     "key": [0,0,0,0],
#     "value": [184,0,0,0,0,0,0,0]
# }]
# (Nota: valor em little-endian — 184 = 0xB8)
```

### 6.2 Ver Programa XDP Carregado

```bash
# Ver programas eBPF carregados
sudo docker exec clab-ebpf-counter-node-b bpftool prog list

# Esperado:
# 4: xdp  name xdp_packet_counter  tag a1b2c3d4e5f6  gpl

# Ver se XDP está anexado à interface
sudo docker exec clab-ebpf-counter-node-b ip link show eth1
# Esperado: ... xdpgeneric  id 4 ...
```

### 6.3 Capturar Tráfego com tcpdump

```bash
# Confirmar que os pacotes estão chegando em node-b
sudo docker exec clab-ebpf-counter-node-b tcpdump -i eth1 -n -c 10

# Esperado: pacotes UDP chegando
# 10:15:30.123456 IP 10.0.0.1.45678 > 10.0.0.2.5201: UDP ...
```

---

## Passo 7 — Desativar e Limpar

### 7.1 Parar o Contador

No terminal onde o `counter` está rodando, pressione:

```
Ctrl+C
```

**Saída esperada:**
```
[145] Total:       26680 | Taxa:        184 pps

[SIGNAL] Descarregando...

[*] Descarregando...
[✓] Saindo...
```

> O programa desanexa automaticamente o XDP da interface ao sair.

### 7.2 Sair do Container node-a

```bash
exit
```

### 7.3 Destruir o Laboratório

```bash
sudo containerlab destroy -t ebpf-counter.clab.yml
```

## 📂 Estrutura do Projeto

```
2_pkt_counter/
├── ebpf-counter.clab.yml   # Definição da topologia Containerlab
├── counter.bpf.c           # Código-fonte eBPF/XDP (roda no kernel)
├── counter.bpf.o           # Bytecode BPF compilado (gerado pelo compile.sh)
├── counter.c               # Loader userspace (carrega XDP + lê BPF Map)
├── counter                 # Executável compilado (gerado pelo compile_us.sh)
├── compile.sh              # Script de compilação eBPF (kernel side) via Docker
├── compile_us.sh           # Script de compilação do loader (userspace) via Docker
└── clab-ebpf-counter/      # Arquivos de runtime gerados pelo Containerlab
    ├── ansible-inventory.yml
    ├── nornir-simple-inventory.yml
    ├── authorized_keys
    └── topology-data.json
```

---

## Referências

- [Documentação Oficial do eBPF](https://ebpf.io/what-is-ebpf/)
- [Documentação do Containerlab](https://containerlab.dev/quickstart/)
- [Tutorial XDP (kernel.org)](https://github.com/xdp-project/xdp-tutorial)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [nicolaka/netshoot — Container de diagnóstico de rede](https://github.com/nicolaka/netshoot)

---

**Sucesso no laboratório!** 🚀
