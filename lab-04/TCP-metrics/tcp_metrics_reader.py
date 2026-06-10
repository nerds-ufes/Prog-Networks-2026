#!/usr/bin/env python3
# tcp_metrics_reader.py
#
# Lê em tempo real as métricas coletadas pelo programa eBPF
# tcp_sockops_metrics.o a partir do mapa pinado em /sys/fs/bpf/tcp_flows
#
# Dependências:
#   sudo apt install python3-bpfcc   # Ubuntu/Debian
#   sudo dnf install python3-bcc     # Fedora/RHEL
#
# Uso:
#   sudo python3 tcp_metrics_reader.py
#   sudo python3 tcp_metrics_reader.py --interval 2 --top 20
#   sudo python3 tcp_metrics_reader.py --filter-ip 192.168.1.100
#   sudo python3 tcp_metrics_reader.py --json

import argparse
import ctypes
import json
import os
import signal
import socket
import struct
import sys
import time
from datetime import datetime

# ---------------------------------------------------------------------------
# Verifica root
# ---------------------------------------------------------------------------
if os.geteuid() != 0:
    print("[erro] Execute com sudo.", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Argumentos
# ---------------------------------------------------------------------------
parser = argparse.ArgumentParser(
    description="Leitor de métricas TCP via mapa eBPF pinado"
)
parser.add_argument("--map",        default="/sys/fs/bpf/tcp_flows",
                    help="Caminho do mapa pinado (padrão: /sys/fs/bpf/tcp_flows)")
parser.add_argument("--interval",   type=float, default=1.0,
                    help="Intervalo de atualização em segundos (padrão: 1)")
parser.add_argument("--top",        type=int,   default=15,
                    help="Máximo de fluxos exibidos por ciclo (padrão: 15)")
parser.add_argument("--filter-ip",  default=None,
                    help="Exibe apenas fluxos envolvendo este IP")
parser.add_argument("--json",       action="store_true",
                    help="Saída em JSON (uma linha por ciclo, para pipelines)")
parser.add_argument("--sort",       default="srtt",
                    choices=["srtt", "cwnd", "retrans", "bytes"],
                    help="Campo de ordenação (padrão: srtt)")
args = parser.parse_args()

# ---------------------------------------------------------------------------
# Estruturas C espelhando o kernel (devem ser idênticas ao .c)
# ---------------------------------------------------------------------------
class TcpFlowKeyIPv4(ctypes.Structure):
    _fields_ = [
        ("src_ip4",  ctypes.c_uint32),
        ("_pad_src", ctypes.c_uint32 * 3),   # union: preenche 4×u32
        ("dst_ip4",  ctypes.c_uint32),
        ("_pad_dst", ctypes.c_uint32 * 3),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("family",   ctypes.c_uint8),
        ("pad",      ctypes.c_uint8 * 3),
    ]

class TcpFlowKeyIPv6(ctypes.Structure):
    _fields_ = [
        ("src_ip6",  ctypes.c_uint32 * 4),
        ("dst_ip6",  ctypes.c_uint32 * 4),
        ("src_port", ctypes.c_uint16),
        ("dst_port", ctypes.c_uint16),
        ("family",   ctypes.c_uint8),
        ("pad",      ctypes.c_uint8 * 3),
    ]

class TcpFlowStats(ctypes.Structure):
    _fields_ = [
        ("srtt_us",         ctypes.c_uint64),
        ("cwnd",            ctypes.c_uint32),
        ("cwnd_max",        ctypes.c_uint32),
        ("ssthresh",        ctypes.c_uint32),
        ("pkts_out",        ctypes.c_uint32),
        ("bytes_acked",     ctypes.c_uint64),
        ("retransmissions", ctypes.c_uint64),
        ("last_bytes_acked",ctypes.c_uint64),
        ("last_segs_out",   ctypes.c_uint64),
        ("timestamp_ns",    ctypes.c_uint64),
    ]

AF_INET  = 2
AF_INET6 = 10

# ---------------------------------------------------------------------------
# Acesso ao mapa via bcc
# ---------------------------------------------------------------------------
try:
    from bcc import table
    from bcc.libbcc import lib as bcc_lib
    import bcc
except ImportError:
    print("[erro] python3-bpfcc não encontrado.", file=sys.stderr)
    print("       Ubuntu: sudo apt install python3-bpfcc", file=sys.stderr)
    print("       Fedora: sudo dnf install python3-bcc", file=sys.stderr)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers de conversão
# ---------------------------------------------------------------------------
def ip4_to_str(n: int) -> str:
    return socket.inet_ntoa(struct.pack("I", n))

def ip6_to_str(words) -> str:
    raw = b"".join(struct.pack("I", w) for w in words)
    return socket.inet_ntop(socket.AF_INET6, raw)

def ns_to_age(ns: int) -> str:
    """Converte timestamp_ns em tempo decorrido legível."""
    now_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    delta  = (now_ns - ns) / 1e9
    if delta < 60:
        return f"{delta:.1f}s"
    elif delta < 3600:
        return f"{delta/60:.1f}m"
    return f"{delta/3600:.1f}h"

def bytes_human(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"

def sort_key(entry):
    k, v = entry
    if args.sort == "srtt":    return v["srtt_us"]
    if args.sort == "cwnd":    return v["cwnd"]
    if args.sort == "retrans": return v["retransmissions"]
    if args.sort == "bytes":   return v["bytes_acked"]
    return 0

# ---------------------------------------------------------------------------
# Abre o mapa pinado
# ---------------------------------------------------------------------------
def open_map(path: str):
    fd = bcc_lib.bpf_obj_get(path.encode())
    if fd < 0:
        print(f"[erro] Não foi possível abrir o mapa: {path}", file=sys.stderr)
        print("       Verifique se o programa eBPF está carregado e o mapa pinado.", file=sys.stderr)
        sys.exit(1)
    return fd

# ---------------------------------------------------------------------------
# Leitura do mapa
# ---------------------------------------------------------------------------
def read_map(map_fd: int) -> dict:
    """Itera sobre todos os elementos do mapa e retorna um dict."""
    flows = {}

    key_buf  = (ctypes.c_uint8 * ctypes.sizeof(TcpFlowKeyIPv6))()
    next_buf = (ctypes.c_uint8 * ctypes.sizeof(TcpFlowKeyIPv6))()
    val_buf  = (ctypes.c_uint8 * ctypes.sizeof(TcpFlowStats))()

    # Inicia iteração com chave nula
    ctypes.memset(key_buf, 0, ctypes.sizeof(key_buf))

    while True:
        ret = bcc_lib.bpf_get_next_key(
            map_fd,
            ctypes.cast(key_buf,  ctypes.c_void_p),
            ctypes.cast(next_buf, ctypes.c_void_p),
        )
        if ret != 0:
            break  # fim da iteração

        # Lê o valor para a next_key encontrada
        ret2 = bcc_lib.bpf_lookup_elem(
            map_fd,
            ctypes.cast(next_buf, ctypes.c_void_p),
            ctypes.cast(val_buf,  ctypes.c_void_p),
        )

        if ret2 == 0:
            family = next_buf[ctypes.sizeof(TcpFlowKeyIPv6) - 4]  # offset do campo family

            if family == AF_INET:
                k = TcpFlowKeyIPv4.from_buffer_copy(next_buf)
                src = f"{ip4_to_str(k.src_ip4)}:{k.src_port}"
                dst = f"{ip4_to_str(k.dst_ip4)}:{k.dst_port}"
            elif family == AF_INET6:
                k = TcpFlowKeyIPv6.from_buffer_copy(next_buf)
                src = f"[{ip6_to_str(k.src_ip6)}]:{k.src_port}"
                dst = f"[{ip6_to_str(k.dst_ip6)}]:{k.dst_port}"
            else:
                ctypes.memmove(key_buf, next_buf, ctypes.sizeof(TcpFlowKeyIPv6))
                continue

            v = TcpFlowStats.from_buffer_copy(val_buf)
            flow_id = f"{src} → {dst}"

            # Filtro de IP (opcional)
            if args.filter_ip and args.filter_ip not in flow_id:
                ctypes.memmove(key_buf, next_buf, ctypes.sizeof(TcpFlowKeyIPv6))
                continue

            flows[flow_id] = {
                "src":            src,
                "dst":            dst,
                "family":         "IPv4" if family == AF_INET else "IPv6",
                "srtt_us":        v.srtt_us,
                "cwnd":           v.cwnd,
                "cwnd_max":       v.cwnd_max,
                "ssthresh":       v.ssthresh,
                "pkts_out":       v.pkts_out,
                "bytes_acked":    v.bytes_acked,
                "retransmissions":v.retransmissions,
                "timestamp_ns":   v.timestamp_ns,
                "age":            ns_to_age(v.timestamp_ns),
            }

        ctypes.memmove(key_buf, next_buf, ctypes.sizeof(TcpFlowKeyIPv6))

    return flows

# ---------------------------------------------------------------------------
# Renderização em tabela
# ---------------------------------------------------------------------------
HEADER = (
    f"{'ORIGEM':<28} {'DESTINO':<28} {'FAM':<5} "
    f"{'RTT(µs)':>9} {'CWND':>6} {'CWND_MAX':>9} {'IN_FLIGHT':>10} "
    f"{'SSTHRESH':>9} {'BYTES_ACK':>11} {'RETRANS':>8} {'IDADE':>7}"
)
SEP = "─" * len(HEADER)

def print_table(flows: dict, cycle: int):
    now = datetime.now().strftime("%H:%M:%S")
    total = len(flows)
    showing = min(total, args.top)

    print(f"\033[2J\033[H", end="")  # limpa tela
    print(f"  tcp_metrics_reader  │  {now}  │  {total} fluxos ativos  │  "
          f"ordenado por: {args.sort}  │  ciclo #{cycle}")
    print(SEP)
    print(HEADER)
    print(SEP)

    sorted_flows = sorted(flows.items(), key=sort_key, reverse=True)[:showing]

    for flow_id, v in sorted_flows:
        src      = v["src"][:27]
        dst      = v["dst"][:27]
        fam      = v["family"]
        srtt     = v["srtt_us"]
        cwnd     = v["cwnd"]
        cwnd_max = v["cwnd_max"]
        pkts_out = v["pkts_out"]
        ssthresh = v["ssthresh"] if v["ssthresh"] < 0xFFFF else "∞"
        bytes    = bytes_human(v["bytes_acked"])
        retrans  = v["retransmissions"]
        age      = v["age"]

        # Destaca RTT alto (> 100 ms) em amarelo
        rtt_str = f"{srtt:>9}"
        if srtt > 100_000:
            rtt_str = f"\033[33m{rtt_str}\033[0m"

        # Destaca retransmissões em vermelho
        ret_str = f"{retrans:>8}"
        if retrans > 0:
            ret_str = f"\033[31m{ret_str}\033[0m"

        # cwnd verde = crescendo (igual ao máximo histórico e > inicial)
        cwnd_str = f"{cwnd:>6}"
        if cwnd > 10 and cwnd == cwnd_max:
            cwnd_str = f"\033[32m{cwnd_str}\033[0m"

        print(
            f"  {src:<28} {dst:<28} {fam:<5} "
            f"{rtt_str} {cwnd_str} {cwnd_max:>9} {pkts_out:>10} "
            f"{str(ssthresh):>9} {bytes:>11} {ret_str} {age:>7}"
        )

    if total > args.top:
        print(f"\n  ... e mais {total - args.top} fluxos (aumente --top para ver)")
    print(SEP)
    print("  Ctrl+C para sair  │  \033[33mamarelo\033[0m = RTT > 100ms  │  "
          "\033[31mvermelho\033[0m = retransmissões  │  \033[32mverde\033[0m = cwnd crescendo")

# ---------------------------------------------------------------------------
# Saída JSON
# ---------------------------------------------------------------------------
def print_json(flows: dict, cycle: int):
    out = {
        "cycle":     cycle,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "flows":     list(flows.values()),
    }
    # timestamp_ns não é serializável diretamente como int em alguns ambientes
    print(json.dumps(out, default=int))

# ---------------------------------------------------------------------------
# Loop principal
# ---------------------------------------------------------------------------
def main():
    map_fd = open_map(args.map)
    cycle  = 0

    def handle_sigint(_sig, _frame):
        print("\n\n[info] Encerrado pelo usuário.")
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    print(f"[info] Mapa aberto: {args.map}")
    print(f"[info] Intervalo: {args.interval}s  |  Top: {args.top}  |  "
          f"Sort: {args.sort}")
    if args.filter_ip:
        print(f"[info] Filtro de IP: {args.filter_ip}")
    time.sleep(0.5)

    while True:
        cycle += 1
        flows = read_map(map_fd)

        if args.json:
            print_json(flows, cycle)
        else:
            print_table(flows, cycle)

        time.sleep(args.interval)

if __name__ == "__main__":
    main()

# Recompila e recarrega:
# sudo clang-18 -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
#   -c tcp_sockops_metrics.c -o tcp_sockops_metrics.o

# sudo rm -f /sys/fs/bpf/tcp_sockops /sys/fs/bpf/tcp_flows
# sudo bpftool prog load tcp_sockops_metrics.o /sys/fs/bpf/tcp_sockops type sockops
# sudo bpftool cgroup attach /sys/fs/cgroup sock_ops \
#   pinned /sys/fs/bpf/tcp_sockops multi

# # Teste com transferência longa para ver o cwnd crescer
# iperf3 -c 172.16.30.105 -t 60 -i 1 &
# sudo python3 tcp_metrics_reader.py --sort cwnd