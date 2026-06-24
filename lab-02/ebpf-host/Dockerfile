FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# Atualiza sistema e instala dependências base para adicionar repositório LLVM
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    wget \
    gnupg \
    lsb-release \
    software-properties-common \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Adiciona repositório oficial do LLVM e instala clang-18
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
        | tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc && \
    echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-18 main" \
        | tee /etc/apt/sources.list.d/llvm-18.list && \
    apt-get update && \
    apt-get install -y clang-18 llvm-18 \
    && rm -rf /var/lib/apt/lists/*

# Cria aliases para que 'clang' e 'llvm-*' apontem para a versão 18
RUN update-alternatives --install /usr/bin/clang      clang      /usr/bin/clang-18      100 && \
    update-alternatives --install /usr/bin/clang++    clang++    /usr/bin/clang++-18    100 && \
    update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-18 100

# Pacotes necessários para eBPF + desenvolvimento
RUN apt-get update && apt-get install -y \
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
    iperf3 \
    linux-headers-6.8.0-106-generic \
    bpfcc-tools \
    python3-bpfcc \
    libbpfcc-dev \
    && rm -rf /var/lib/apt/lists/*

# Instala bibliotecas Python para eBPF
RUN pip3 install --no-cache-dir \
    pyroute2 \
    scapy \
    numpy \
    matplotlib \
    pandas

RUN pip3 install --no-cache-dir pytest

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
