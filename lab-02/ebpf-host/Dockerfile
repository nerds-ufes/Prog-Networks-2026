FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Atualiza sistema
RUN apt-get update && apt-get upgrade -y

# Pacotes base + dependências para adicionar repositório LLVM
RUN apt-get install -y \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    ca-certificates

# Adiciona repositório oficial do LLVM e instala clang-18
# Sem 'sudo' (container já roda como root) e com apt-get -y (não interativo)
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
        | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-18 main" \
        | tee /etc/apt/sources.list.d/llvm-18.list && \
    apt-get update && \
    apt-get install -y clang-18 llvm-18

# Cria aliases para que 'clang' e 'llvm-*' apontem para a versão 18
# Necessário para Makefiles que chamam 'clang' sem sufixo de versão
RUN update-alternatives --install /usr/bin/clang      clang      /usr/bin/clang-18      100 && \
    update-alternatives --install /usr/bin/clang++    clang++    /usr/bin/clang++-18    100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-18 100

# Pacotes necessários para eBPF + desenvolvimento
RUN apt-get install -y \
    build-essential \
    nano \
    libssl-dev \
    libelf-dev \
    libbpf-dev \
    libpcap-dev \
    zlib1g-dev \
    gcc-multilib \
    make \
    cmake \
    git \
    pkg-config \
    curl \
    vim \
    iproute2 \
    net-tools \
    tcpdump \
    python3 \
    python3-pip \
    python3-dev \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    libcap-dev \
    libnuma-dev \
    dwarves \
    pahole \
    trace-cmd \
    iputils-ping \
    iperf3

RUN apt update && \
    apt install -y linux-headers-6.8.0-106-generic

# Instala bibliotecas Python para eBPF
RUN pip3 install --no-cache-dir \
    pyroute2 \
    scapy \
    numpy \
    matplotlib \
    pandas \
    bcc

RUN pip3 install pytest

RUN pip uninstall -y bcc || true

RUN apt update && apt install -y \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev

# Compila bpftool direto do kernel source
# (garante compatibilidade independente do kernel do host)
RUN git clone --depth 1 https://github.com/torvalds/linux.git /linux-src && \
    cd /linux-src/tools/bpf/bpftool && \
    make && \
    make install && \
    cd / && rm -rf /linux-src

# Diretório de trabalho
WORKDIR /root
CMD ["/bin/bash"]
