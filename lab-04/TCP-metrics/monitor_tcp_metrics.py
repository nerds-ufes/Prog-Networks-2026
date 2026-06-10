#!/usr/bin/env python3

import subprocess
import json
import time
import socket
import struct
import sys

# MAP_PATH = "/sys/fs/bpf/xdp/globals/flows"
MAP_PATH = "/sys/fs/bpf/tcp_flows"

def ip_to_str(ip):
    # Corrige endianness
    return socket.inet_ntoa(struct.pack("<I", ip))


def run_bpftool():
    cmd = ["sudo", "bpftool", "-j", "map", "dump", "pinned", MAP_PATH]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("Erro executando bpftool")
        print(result.stderr)
        return None

    return json.loads(result.stdout)


# def print_metrics(entries, filter_src, filter_dst):

#     print("\n================ TCP FLOW METRICS ================")

#     for entry in entries:

#         key = entry["formatted"]["key"]
#         value = entry["formatted"]["value"]

#         src_ip = ip_to_str(key["src_ip"])
#         dst_ip = ip_to_str(key["dst_ip"])

#         # ✅ filtro por argumento
#         if filter_src and filter_dst:
#             if not (
#                 (src_ip == filter_src and dst_ip == filter_dst) or
#                 (src_ip == filter_dst and dst_ip == filter_src)
#             ):
#                 continue
#         # if filter_src and src_ip != filter_src:
#         #     continue
#         # if filter_dst and dst_ip != filter_dst:
#         #     continue

#         src_port = key["src_port"]
#         dst_port = key["dst_port"]

#         bytes_seen = value["bytes_seen"]
#         retrans = value["retransmissions"]
#         inflight = value["inflight_bytes"]
#         max_inflight = value["max_inflight"]

#         rtt_count = value["rtt_count"]
#         rtt_sum = value["rtt_sum_ns"]

#         avg_rtt = (rtt_sum / rtt_count) / 1e6 if rtt_count > 0 else 0

#         print(f"\nFlow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
#         print(f"Bytes: {bytes_seen}")
#         print(f"Retransmissões: {retrans}")
#         print(f"In-flight: {inflight}")
#         print(f"Max in-flight: {max_inflight}")
#         print(f"RTT médio (ms): {avg_rtt:.3f}")

def print_metrics(entries, filter_src, filter_dst):

    print("\n================ TCP FLOW METRICS (AGREGADO) ================")

    flows_agg = {}

    for entry in entries:

        key = entry["formatted"]["key"]
        value = entry["formatted"]["value"]

        src_ip_int = key["src_ip"]
        dst_ip_int = key["dst_ip"]

        src_ip = ip_to_str(src_ip_int)
        dst_ip = ip_to_str(dst_ip_int)

        # ✅ filtro por IP (bidirecional)
        if filter_src and filter_dst:
            if not (
                (src_ip == filter_src and dst_ip == filter_dst) or
                (src_ip == filter_dst and dst_ip == filter_src)
            ):
                continue

        # ✅ filtro por porta (iperf)
        if key["src_port"] != 5201 and key["dst_port"] != 5201:
            continue

        # ✅ ignora fluxos vazios
        if value["bytes_seen"] == 0:
            continue

        # 🔥 chave agregada (ignora direção)
        flow_id = tuple(sorted([src_ip_int, dst_ip_int]))

        if flow_id not in flows_agg:
            flows_agg[flow_id] = {
                "bytes": 0,
                "retrans": 0,
                "inflight": 0,
                "max_inflight": 0,
                "rtt_sum": 0,
                "rtt_count": 0
            }

        flows_agg[flow_id]["bytes"] += value["bytes_seen"]
        flows_agg[flow_id]["retrans"] += value["retransmissions"]
        flows_agg[flow_id]["inflight"] += value["inflight_bytes"]
        flows_agg[flow_id]["max_inflight"] = max(
            flows_agg[flow_id]["max_inflight"],
            value["max_inflight"]
        )

        flows_agg[flow_id]["rtt_sum"] += value["rtt_sum_ns"]
        flows_agg[flow_id]["rtt_count"] += value["rtt_count"]

    # 🔥 impressão FINAL (fora do loop)
    for flow_id, stats in flows_agg.items():

        src_ip = ip_to_str(flow_id[0])
        dst_ip = ip_to_str(flow_id[1])

        if stats["rtt_count"] > 0:
            avg_rtt = (stats["rtt_sum"] / stats["rtt_count"]) / 1e6
        else:
            avg_rtt = 0

        print(f"\nFlow (AGREGADO): {src_ip} <-> {dst_ip}")
        print(f"Bytes: {stats['bytes']}")
        print(f"Retransmissões: {stats['retrans']}")
        print(f"In-flight: {stats['inflight']}")
        print(f"Max in-flight: {stats['max_inflight']}")
        print(f"RTT médio (ms): {avg_rtt:.3f}")

def main():

    # argumentos opcionais
    filter_src = None
    filter_dst = None

    if len(sys.argv) == 3:
        filter_src = sys.argv[1]
        filter_dst = sys.argv[2]
    elif len(sys.argv) != 1:
        print("Uso:")
        print("  sudo python3 monitor_tcp_metrics.py [SRC_IP DST_IP]")
        return

    print("Monitorando métricas TCP do XDP...\n")

    if filter_src:
        print(f"Filtro aplicado: {filter_src} -> {filter_dst}\n")

    while True:

        entries = run_bpftool()

        if entries is not None:
            print_metrics(entries, filter_src, filter_dst)

        time.sleep(2)


if __name__ == "__main__":
    main()
