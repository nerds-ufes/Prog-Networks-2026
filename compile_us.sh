#!/bin/bash
set -e

echo "Compilando Counter C usando Docker (Ubuntu 24.04 - kernel 6.8+)..."

# Usar Ubuntu 24.04 (kernel mais novo!)
sudo docker run --rm -v $(pwd):/code -w /code ubuntu:24.04 /bin/bash -c "
    apt-get update && \
    apt-get install -y gcc libbpf-dev libelf-dev zlib1g-dev && \
    gcc -O2 -Wall counter.c -o counter \
        -lbpf -lelf -lz
"

sudo chmod +x counter

if [ -f counter ]; then
    echo "Success! loader counter created.🍻🍻🍻"
else
    echo "Compilação falhou.❌"
    exit 1
fi

