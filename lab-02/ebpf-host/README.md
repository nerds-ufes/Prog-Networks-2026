# ebpf-host — Imagem Docker para Desenvolvimento eBPF

Imagem Docker baseada em **Ubuntu 22.04** com ambiente completo para desenvolvimento, compilação e execução de programas eBPF. Inclui toolchain LLVM/Clang 18, libbpf, bpftool compilado do fonte, ferramentas de rede e bibliotecas Python para análise e scripting.

Utilizada como imagem base de todos os nós do laboratório `lab-04` (hosts e switches).

---

## Sumário

1. [Visão geral](#1-visão-geral)
2. [Build da imagem](#2-build-da-imagem)
3. [Camadas do Dockerfile](#3-camadas-do-dockerfile)
   - [Base e atualização do sistema](#base-e-atualização-do-sistema)
   - [Toolchain LLVM/Clang 18](#toolchain-llvmclang-18)
   - [Aliases de compilador](#aliases-de-compilador)
   - [Pacotes de desenvolvimento eBPF e rede](#pacotes-de-desenvolvimento-ebpf-e-rede)
   - [Headers do kernel fixo](#headers-do-kernel-fixo)
   - [Bibliotecas Python](#bibliotecas-python)
   - [BCC (BPF Compiler Collection)](#bcc-bpf-compiler-collection)
   - [bpftool compilado do fonte](#bpftool-compilado-do-fonte)
4. [Ferramentas disponíveis](#4-ferramentas-disponíveis)
5. [Uso da imagem](#5-uso-da-imagem)
6. [Notas e observações](#6-notas-e-observações)

---

## 1. Visão geral

| Propriedade       | Valor                        |
|-------------------|------------------------------|
| Imagem base       | `ubuntu:22.04`               |
| Compilador BPF    | `clang-18` / `llvm-18`       |
| `bpftool`         | Compilado do fonte (`linux.git`) |
| Diretório padrão  | `/root`                      |
| Entrypoint        | `/bin/bash`                  |

A imagem **não define** `USER`, `EXPOSE` nem volumes — opera como `root` e é projetada para uso em ambientes de laboratório isolados (containerlab).

---

## 2. Build da imagem

```bash
docker build -t ebpf-host:latest .
```

> ⚠️ O build clona o repositório do kernel Linux (`torvalds/linux`) para compilar o `bpftool`. Isso requer **conexão à internet** e pode demorar vários minutos na primeira execução. O diretório clonado é removido ao final para não inflar a imagem.

Para rebuild sem cache (útil após mudanças no Dockerfile):

```bash
docker build --no-cache -t ebpf-host:latest .
```

Para rebuild aproveitando cache das camadas anteriores:

```bash
docker build --cache-from ebpf-host:latest -t ebpf-host:latest .
```

---

## 3. Camadas do Dockerfile

### Base e atualização do sistema

```dockerfile
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get upgrade -y
```

`DEBIAN_FRONTEND=noninteractive` suprime prompts interativos do `apt` durante o build — necessário para instalação não assistida de pacotes com configuração pós-instalação (ex: `tzdata`).

---

### Toolchain LLVM/Clang 18

```dockerfile
RUN apt-get install -y wget gnupg lsb-release software-properties-common ca-certificates

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
        | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-18 main" \
        | tee /etc/apt/sources.list.d/llvm-18.list && \
    apt-get update && \
    apt-get install -y clang-18 llvm-18
```

O LLVM 18 é instalado a partir do **repositório oficial do projeto LLVM** (`apt.llvm.org`), não do repositório padrão do Ubuntu — que distribuiria uma versão mais antiga. A chave GPG é adicionada via `trusted.gpg.d` (método recomendado para Ubuntu 22.04+).

---

### Aliases de compilador

```dockerfile
RUN update-alternatives --install /usr/bin/clang      clang      /usr/bin/clang-18      100 && \
    update-alternatives --install /usr/bin/clang++    clang++    /usr/bin/clang++-18    100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-18 100
```

Cria aliases sem sufixo de versão (`clang`, `clang++`, `llvm-strip`) apontando para os binários do LLVM 18. Necessário para que `Makefiles` e scripts que invocam `clang` diretamente funcionem sem modificação.

---

### Pacotes de desenvolvimento eBPF e rede

```dockerfile
RUN apt-get install -y \
    build-essential libssl-dev libelf-dev libbpf-dev libpcap-dev \
    zlib1g-dev gcc-multilib make cmake git pkg-config curl \
    nano vim \
    iproute2 net-tools tcpdump iputils-ping iperf3 \
    linux-headers-generic linux-tools-common linux-tools-generic \
    libcap-dev libnuma-dev dwarves pahole trace-cmd \
    python3 python3-pip python3-dev
```

Agrupados por categoria:

| Categoria              | Pacotes                                                    |
|------------------------|------------------------------------------------------------|
| Build essencial        | `build-essential`, `make`, `cmake`, `git`, `pkg-config`   |
| Bibliotecas eBPF       | `libelf-dev`, `libbpf-dev`, `libpcap-dev`, `libcap-dev`   |
| Bibliotecas de sistema | `libssl-dev`, `zlib1g-dev`, `libnuma-dev`, `gcc-multilib` |
| Ferramentas de rede    | `iproute2`, `net-tools`, `tcpdump`, `iputils-ping`, `iperf3` |
| Kernel / BPF tools     | `linux-headers-generic`, `linux-tools-generic`, `dwarves`, `pahole`, `trace-cmd` |
| Python                 | `python3`, `python3-pip`, `python3-dev`                   |
| Editores               | `nano`, `vim`                                             |

`pahole` e `dwarves` são necessários para geração e manipulação de BTF (BPF Type Format), usado em programas eBPF com CO-RE.

---

### Headers do kernel fixo

```dockerfile
RUN apt update && \
    apt install -y linux-headers-6.8.0-106-generic
```

Instala headers de uma versão **específica e fixada** do kernel (`6.8.0-106`). Isso garante que a compilação de programas eBPF dentro do container tenha headers compatíveis com o kernel do host do laboratório, independentemente da versão genérica disponível no repositório.

> ⚠️ Se o kernel do host for atualizado, este número pode precisar ser ajustado no Dockerfile.

---

### Bibliotecas Python

```dockerfile
RUN pip3 install --no-cache-dir \
    pyroute2 scapy numpy matplotlib pandas bcc

RUN pip3 install pytest
```

| Biblioteca   | Finalidade                                              |
|--------------|---------------------------------------------------------|
| `pyroute2`   | Manipulação de interfaces, rotas e mapas netlink via Python |
| `scapy`      | Criação e análise de pacotes de rede                    |
| `numpy`      | Computação numérica (análise de métricas)               |
| `matplotlib` | Geração de gráficos (visualização de resultados)        |
| `pandas`     | Manipulação de dados tabulares (ex: saídas de iperf3)   |
| `bcc`        | BPF Compiler Collection — Python bindings para eBPF     |
| `pytest`     | Framework de testes                                     |

---

### BCC (BPF Compiler Collection)

```dockerfile
RUN pip uninstall -y bcc || true

RUN apt update && apt install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev
```

O `bcc` instalado via `pip` é desinstalado antes de reinstalar via `apt`. Isso resolve um conflito comum: a versão `pip` do `bcc` pode ser incompatível com a versão do `libbpfcc` do sistema, causando erros de importação em tempo de execução. A versão via `apt` é compilada contra as bibliotecas do sistema e garante consistência.

| Pacote           | Conteúdo                                              |
|------------------|-------------------------------------------------------|
| `bpfcc-tools`    | Ferramentas de linha de comando do BCC (`execsnoop`, `biolatency`, etc.) |
| `python3-bpfcc`  | Bindings Python para programação BPF via BCC          |
| `libbpfcc-dev`   | Headers e bibliotecas de desenvolvimento do BCC       |

---

### bpftool compilado do fonte

```dockerfile
RUN git clone --depth 1 https://github.com/torvalds/linux.git /linux-src && \
    cd /linux-src/tools/bpf/bpftool && \
    make && \
    make install && \
    cd / && rm -rf /linux-src
```

O `bpftool` é compilado diretamente do repositório do kernel Linux em vez de ser instalado via `apt`. Motivações:

- A versão do `apt` pode estar desatualizada e não suportar features recentes (ex: `struct_ops register`).
- Compilar do fonte garante compatibilidade com a versão de `libbpf` presente na imagem.
- `--depth 1` faz um clone raso (apenas o commit mais recente), minimizando o tamanho do download.
- O diretório `/linux-src` é removido ao final, evitando que o clone (~1 GB) permaneça na imagem final.

> ℹ️ O `bpftool` é instalado em `/usr/local/sbin/bpftool` por padrão após `make install`.

---

## 4. Ferramentas disponíveis

Após o build, a imagem oferece:

### Compilação eBPF

| Ferramenta     | Versão / Origem         | Comando             |
|----------------|-------------------------|---------------------|
| `clang`        | 18 (LLVM oficial)       | `clang --version`   |
| `clang++`      | 18 (LLVM oficial)       | `clang++ --version` |
| `llvm-strip`   | 18 (LLVM oficial)       | `llvm-strip --version` |
| `bpftool`      | Compilado do fonte      | `bpftool version`   |

### Rede e diagnóstico

| Ferramenta   | Finalidade                              |
|--------------|-----------------------------------------|
| `iperf3`     | Teste de throughput TCP/UDP             |
| `tcpdump`    | Captura e análise de pacotes            |
| `ping`       | Teste de conectividade ICMP             |
| `ip`         | Configuração de interfaces e rotas      |
| `ss`         | Inspeção de sockets TCP (cwnd, rtt...)  |
| `tc`         | Traffic control (netem, tbf, qdisc)     |
| `trace-cmd`  | Tracing de eventos do kernel            |

### BCC / Python

| Ferramenta         | Finalidade                                   |
|--------------------|----------------------------------------------|
| `python3`          | Scripts de análise e automação               |
| `python3-bpfcc`    | Programação eBPF via Python                  |
| `bpfcc-tools`      | Ferramentas BCC prontas (`execsnoop`, etc.)  |
| `pyroute2`         | Manipulação de rede via Python               |
| `scapy`            | Geração e análise de pacotes via Python      |
| `matplotlib/pandas`| Análise e visualização de métricas           |

---

## 5. Uso da imagem

### Executar container interativo

```bash
docker run --rm -it \
  --privileged \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /lib/modules:/lib/modules \
  ebpf-host:latest
```

> `--privileged` é necessário para operações eBPF (carregamento de programas, criação de mapas, acesso a `struct_ops`).

### Compilar um programa eBPF dentro do container

```bash
docker run --rm -v $(pwd):/work -w /work ebpf-host:latest \
  clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -Wall -c programa.bpf.c -o programa.bpf.o
```

### Uso no containerlab (lab-04)

No `topology-04.yml`, os nós montam recursos do host diretamente:

```yaml
binds:
  - /sys/fs/bpf:/sys/fs/bpf
  - /lib/modules:/lib/modules
  - /usr/sbin/bpftool:/usr/sbin/bpftool
  - /boot:/boot
```

> ℹ️ O `bpftool` montado via bind (`/usr/sbin/bpftool`) vem do **host**, não da imagem. Isso pode conflitar com a versão compilada do fonte caso os dois caminhos divirjam. Para usar o `bpftool` da imagem, remova o bind correspondente do arquivo de topologia.

---

## 6. Notas e observações

- **Tamanho da imagem** — a imagem resultante é grande (vários GB), principalmente devido ao LLVM 18, BCC e às dependências de desenvolvimento. Para produção, considere usar multi-stage builds separando o ambiente de compilação do de execução.

- **Headers fixados em `6.8.0-106`** — se o kernel do host for diferente, programas eBPF que dependem de headers específicos podem falhar na compilação. Atualize a versão no Dockerfile conforme necessário:
  ```bash
  uname -r  # verifique a versão do kernel do host
  ```

- **`bcc` desinstalado do pip antes de reinstalar via apt** — a sequência `pip uninstall bcc → apt install python3-bpfcc` é intencional e resolve conflitos de biblioteca em tempo de execução. Não altere a ordem.

- **Clone do kernel para bpftool** — o `git clone` do repositório `torvalds/linux` é a etapa mais demorada e sensível a conectividade. Em ambientes sem acesso à internet, substitua por uma cópia local ou use `COPY` de um tarball pré-baixado.

- **Sem usuário não-root** — a imagem opera como `root`. Para uso em ambientes onde isso é uma restrição, adicione um `USER` no final do Dockerfile e ajuste as permissões dos diretórios necessários.

- **`WORKDIR /root`** — o diretório de trabalho padrão é `/root`. Arquivos copiados via `docker cp` (como feito pelo `start.sh`) chegam em `/root/` dentro do container.
