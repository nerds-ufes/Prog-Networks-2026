#!/bin/bash
set -e

echo "Compilando programa eBPF (kernel side) usando Docker..."

# Usa Ubuntu 22.04 como builder com clang e libbpf headers
# Monta o diretório atual em /code dentro do container
sudo docker run --rm -v $(pwd):/code -w /code ubuntu:22.04 /bin/bash -c "
    apt-get update && \
    apt-get install -y clang llvm libbpf-dev gcc-multilib && \
    clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c counter.bpf.c -o counter.bpf.o
"

if [ -f counter.bpf.o ]; then
    echo "Success! counter.bpf.o created.🍻🍻🍻"
else
    echo "Compilation failed.❌"
    exit 1
fi