# 🛡️ Laboratório XDP/eBPF com Containerlab

> Laboratório prático de **filtragem de pacotes em velocidade de linha** usando **eBPF/XDP** em um ambiente de rede virtualizado com **Containerlab**.

[![Containerlab](https://img.shields.io/badge/Containerlab-v0.50+-blue?logo=linux)](https://containerlab.dev)
[![Docker](https://img.shields.io/badge/Docker-required-blue?logo=docker)](https://www.docker.com)
[![eBPF](https://img.shields.io/badge/eBPF-XDP-orange)](https://ebpf.io)
[![Licença](https://img.shields.io/badge/licença-GPL--2.0-green)](LICENSE)

---

## 📖 Visão Geral

Este laboratório demonstra um dos recursos mais poderosos do kernel Linux: o **XDP (eXpress Data Path)**. Aqui é anexado um pequeno programa eBPF na interface de rede, que descarta pacotes **antes mesmo que eles cheguem à pilha de rede**, tornando a filtragem praticamente "gratuita" em termos de CPU.

**O que este laboratório demonstra:**
- Compilação de um programa eBPF em C para bytecode BPF usando Docker como ambiente de build.
- Deploy de uma rede virtual com 2 nós usando Containerlab.
- Carregamento de um programa XDP em uma interface de rede com `bpftool`.
- Bloqueio de tráfego ICMP (ping) em velocidade de linha.
- Leitura de contadores de pacotes descartados a partir de um **BPF Map** em tempo real.

---

## 🗺️ Topologia

```
┌─────────────────────────────────────────┐
│               Máquina Host              │
│                                         │
│  ┌──────────┐ eth1   eth1 ┌──────────┐  │
│  │  node-a  ├─────────────┤  node-b  │  │
│  │10.0.0.1  │             │10.0.0.2  │  │
│  └──────────┘             └──────────┘  │
│    (emissor)            (filtro XDP) 🛡️ │
└─────────────────────────────────────────┘
```

| Nó     | Endereço IP  | Função                                      |
|--------|-------------|---------------------------------------------|
| node-a | `10.0.0.1`  | Emissor de pacotes (origem do ping)         |
| node-b | `10.0.0.2`  | Filtro XDP — descarta pacotes ICMP          |

---

## 🔧 Pré-requisitos

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

## 🐝 Obtendo o Laboratório

Clone o repositório e acesse o diretório do laboratório:

```bash
git clone https://github.com/DANIELVENTORIM/ebpf-lab.git
cd ebpf-lab
```

> 📁 Arquivos principais:
> - `lab-ebpf.clab.yml` — Definição da topologia Containerlab
> - `xdp_drop.c` — Código-fonte eBPF/XDP
> - `compile.sh` — Script de compilação via Docker

---

## 🐝 Passo 1 — Compilar o Programa eBPF

O script `compile.sh` usa um **container Ubuntu 22.04 como ambiente de build**, dispensando a instalação de ferramentas de compilação no host.

```bash
# Se não estiver no diretório do lab:
# cd ~/redes/ebpf-lab
./compile.sh
```

<details>
<summary>O que o compile.sh faz?</summary>

Ele sobe um container Docker temporário que:
1. Instala `clang`, `llvm`, `libbpf-dev` e `gcc-multilib`.
2. Compila `xdp_drop.c` gerando bytecode para a **máquina virtual BPF** (`-target bpf`).
3. Gera o arquivo objeto `xdp_drop.o` no diretório atual.
4. Remove o container de build automaticamente (`--rm`).

</details>

**Saída esperada:**
```
Success! xdp_drop.o created.🍻🍻🍻
```

---

## 🌐 Passo 2 — Deploy da Topologia

```bash
sudo containerlab deploy -t lab-ebpf.clab.yml --reconfigure
```

Isso irá:
- Criar dois containers Linux (`node-a` e `node-b`) com a imagem `nicolaka/netshoot`.
- Configurar os IPs nas interfaces `eth1` de cada nó.
- Montar o `xdp_drop.o` dentro do `node-b` em `/xdp_drop.o`.
- Criar um link virtual direto entre as interfaces `eth1` dos dois nós.

Verifique se o lab está rodando:

```bash
docker ps --filter "label=containerlab=ebpf-lab"
```

---

## ✅ Passo 3 — Verificar Conectividade Inicial

Antes de ativar o filtro XDP, confirme que os nós se comunicam normalmente:

```bash
docker exec clab-ebpf-lab-node-a ping -c 3 10.0.0.2
```

**Resultado esperado:** `0% packet loss` ✅

---

## 🛡️ Passo 4 — Ativar o Filtro XDP

### 4.1 Instalar o bpftool no node-b

```bash
sudo docker exec clab-ebpf-lab-node-b apk add bpftool
```

### 4.2 Carregar e pinar o programa XDP

```bash
# Remover pin anterior (se existir) para evitar erros
sudo docker exec clab-ebpf-lab-node-b rm -f /sys/fs/bpf/xdp_test

# Carregar e pinar o programa no filesystem BPF
sudo docker exec clab-ebpf-lab-node-b \
  bpftool prog load /xdp_drop.o /sys/fs/bpf/xdp_test type xdp

# Anexar à interface eth1
sudo docker exec clab-ebpf-lab-node-b \
  ip link set dev eth1 xdpgeneric pinned /sys/fs/bpf/xdp_test
```

> **Por que pinar?** Pinar o programa em `/sys/fs/bpf/` mantém o BPF Map ativo na memória, permitindo ler o contador de drops mesmo após o comando de carregamento encerrar.

---

## 🧪 Passo 5 — Teste e Verificação

### 5.1 Confirmar que o ICMP está bloqueado

```bash
sudo docker exec clab-ebpf-lab-node-a ping -c 5 10.0.0.2
```

**Resultado esperado:** `100% packet loss` 🚫

### 5.2 Ler o contador de drops do BPF Map

```bash
sudo docker exec clab-ebpf-lab-node-b bpftool map dump name packet_count_ma
```

> *(O nome do mapa pode aparecer truncado como `packet_count_ma`; você pode usar `bpftool map show` para ver o ID.)*

**Resultado esperado:**
```json
[{
    "key": 0,
    "value": 5
}]
```

> O contador incrementa atomicamente a cada pacote ICMP descartado — seguro até em múltiplos núcleos de CPU.

---

## 🔓 Passo 6 — Desativar o Filtro

Para restaurar o tráfego ICMP normal:

```bash
sudo docker exec clab-ebpf-lab-node-b ip link set dev eth1 xdpgeneric off
```

Verifique que a conectividade foi restaurada:

```bash
sudo docker exec clab-ebpf-lab-node-a ping -c 3 10.0.0.2
```

**Resultado esperado:** `0% packet loss` ✅

---

## 🧹 Limpeza

Para destruir o laboratório e remover todos os containers:

```bash
sudo containerlab destroy -t lab-ebpf.clab.yml
```

---

## 📂 Estrutura do Projeto

```
ebpf-lab/
├── lab-ebpf.clab.yml        # Definição da topologia Containerlab
├── xdp_drop.c               # Código-fonte eBPF/XDP (drop ICMP + contador)
├── xdp_drop.o               # Bytecode BPF compilado (gerado pelo compile.sh)
├── compile.sh               # Script de compilação eBPF via Docker
├── ativation-test.md        # Guia de referência rápida
└── clab-ebpf-lab/           # Arquivos de runtime gerados pelo Containerlab
    ├── ansible-inventory.yml
    ├── nornir-simple-inventory.yml
    ├── authorized_keys
    └── topology-data.json
```

---

## 📚 Referências

- [Documentação Oficial do eBPF](https://ebpf.io/what-is-ebpf/)
- [Documentação do Containerlab](https://containerlab.dev/quickstart/)
- [Tutorial XDP (kernel.org)](https://github.com/xdp-project/xdp-tutorial)
- [libbpf GitHub](https://github.com/libbpf/libbpf)
- [nicolaka/netshoot — Container de diagnóstico de rede](https://github.com/nicolaka/netshoot)
