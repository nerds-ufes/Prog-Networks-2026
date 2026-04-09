#!/bin/bash

# Script para compilar, carregar e anexar programa BPF sockops
# Uso: ./load.sh

# # Teste com transferência longa para ver o cwnd crescer
# iperf3 -c 172.16.30.105 -t 60 -i 1 &
# sudo python3 tcp_metrics_reader.py --sort cwnd

echo "Compilando programa BPF sockops..."
clang-18 -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
  -c tcp_sockops_metrics.c -o tcp_sockops_metrics.o

echo "Removendo path ..."
rm -f /sys/fs/bpf/tcp_sockops /sys/fs/bpf/tcp_flows

echo "Configurando path /sys/fs/bpf/tcp_sockops ..."
bpftool prog load tcp_sockops_metrics.o /sys/fs/bpf/tcp_sockops type sockops

echo "Carregando prog eBPF ..."
bpftool cgroup attach /sys/fs/cgroup sock_ops \
  pinned /sys/fs/bpf/tcp_sockops multi
