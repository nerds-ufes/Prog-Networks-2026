// tcp_metrics_xdp.c
// XDP program para coletar métricas TCP por fluxo (bytes, retransmissões, inflight estimado).
// Nota: XDP é só ingress — RTT/bytes_acked só serão observáveis se ACKs também passarem pela mesma XDP.
// Compilar: sudo clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c tcp_metrics_xdp.c -o tcp_metrics_xdp.o
// Carregar: sudo ip link set dev enp1s0 xdp obj tcp_metrics_xdp.o sec xdp
// Descarregar: sudo ip link set dev enp1s0 xdp off
// Verificando: sudo ip link show dev enp1s0
// Ler maps: sudo bpftool map dump pinned /sys/fs/bpf/xdp/globals/flows -p

// O código funciona, mas como a interface usa xdpgeneric, não consegue capturar todos os
// pacotes logo, para testes, deve ser usada uma taxa menor: sudo iperf3 -c 172.16.30.105 -t 100 -R -b 500k
// Outro problema, o rtt é sempre 0, pois o programa não está capturando os ACKs (que raramente passam pela mesma XDP). Para testar o rtt, pode-se usar uma ferramenta como tcpreplay para enviar pacotes pré-capturados, garantindo que os ACKs também sejam vistos pela XDP.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#define MAX_FLOWS 16384
#define MAX_SEQ_ENTRIES 65536

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 proto;
    __u8 pad;
};

struct flow_stats {
    __u64 bytes_seen;        // bytes observados (a partir do src->dst)
    __u64 retransmissions;   // contagem de retransmissões (mesmo seq visto de novo)
    __u64 last_seen_ts;      // ns
    __u64 rtt_sum_ns;        // só atualiza se ACKs forem observados no mesmo XDP
    __u32 rtt_count;
    __u64 inflight_bytes;    // estimativa: bytes_seen - bytes_acked (bytes_acked só se ACKs vistos)
    __u64 max_inflight;
};

struct seq_key {
    struct flow_key f;
    __u32 seq;
};

// Map de fluxos, pinado para acesso user-space
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} flows SEC(".maps");

// Map de timestamps por seq (para detectar retransmissões e, possivelmente, RTT)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SEQ_ENTRIES);
    __type(key, struct seq_key);
    __type(value, __u64);
} seq_ts SEC(".maps");

// Alvo opcional (em network order). Comente/desative para monitorar todo tráfego.
#ifndef MONITOR_TARGET_IP
// #define MONITOR_TARGET_IP bpf_htonl(0xAC101E69) // 172.16.30.105
#endif

static __always_inline void *ptr_add(void *p, __u64 off) {
    return (void *)((__u8 *)p + off);
}

static __always_inline int parse_and_update(void *data, void *data_end) {
    // check ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto != ETH_P_IP) return XDP_PASS;

    // ip header
    struct iphdr *ip = ptr_add(data, sizeof(*eth));
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    // tcp header
    struct tcphdr *tcp = ptr_add(ip, ip_hdr_len);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;
    int tcp_hdr_len = tcp->doff * 4;

    // total length from IP
    __u32 total_len = bpf_ntohs(ip->tot_len);
    if (total_len < (unsigned)(ip_hdr_len + tcp_hdr_len)) return XDP_PASS;
    __u32 tcp_payload = total_len - ip_hdr_len - tcp_hdr_len;

    // build flow key (src -> dst as seen on ingress)
    struct flow_key fk = {};
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 src_port = bpf_ntohs(tcp->source);
    __u16 dst_port = bpf_ntohs(tcp->dest);

    // 🔥 NORMALIZA (ordena sempre igual)
    if (src_ip < dst_ip || (src_ip == dst_ip && src_port < dst_port)) {
        fk.src_ip = src_ip;
        fk.dst_ip = dst_ip;
        fk.src_port = src_port;
        fk.dst_port = dst_port;
    } else {
        fk.src_ip = dst_ip;
        fk.dst_ip = src_ip;
        fk.src_port = dst_port;
        fk.dst_port = src_port;
    }
    // fk.src_ip = ip->saddr;
    // fk.dst_ip = ip->daddr;
    // fk.src_port = bpf_ntohs(tcp->source);
    // fk.dst_port = bpf_ntohs(tcp->dest);
    fk.proto = IPPROTO_TCP;

#ifdef MONITOR_TARGET_IP
    // se definido, filtra (monitorar só um destino)
    if (fk.dst_ip != MONITOR_TARGET_IP && fk.src_ip != MONITOR_TARGET_IP) {
        return XDP_PASS;
    }
#endif

    // lookup or create flow stats
    struct flow_stats zero = {};
    struct flow_stats *fs = bpf_map_lookup_elem(&flows, &fk);
    if (!fs) {
        bpf_map_update_elem(&flows, &fk, &zero, BPF_NOEXIST);
        fs = bpf_map_lookup_elem(&flows, &fk);
        if (!fs) return XDP_PASS;
    }

    __u64 now = bpf_ktime_get_ns();
    fs->last_seen_ts = now;

    // If payload bytes > 0, treat as data going src->dst
    if (tcp_payload > 0) {
        // increment bytes_seen and inflight
        __sync_fetch_and_add(&fs->bytes_seen, tcp_payload);
        __sync_fetch_and_add(&fs->inflight_bytes, tcp_payload);
        // update max_inflight (non-atomic compare/update but acceptable approximation)
        if (fs->inflight_bytes > fs->max_inflight) {
            fs->max_inflight = fs->inflight_bytes;
        }

        // sequence-based timestamp for RTT/retrans detection
        __u32 seq = bpf_ntohl(tcp->seq);
        struct seq_key sk = {};
        sk.f = fk;
        sk.seq = seq;

        __u64 *prev = bpf_map_lookup_elem(&seq_ts, &sk);
        if (prev) {
            // same seq seen before -> retransmission (approx)
            __sync_fetch_and_add(&fs->retransmissions, 1);
            // update timestamp
            bpf_map_update_elem(&seq_ts, &sk, &now, BPF_ANY);
        } else {
            bpf_map_update_elem(&seq_ts, &sk, &now, BPF_NOEXIST);
        }
    } else {
        // payload == 0 : could be pure ACK (from server to client). But on ingress we rarely see ACKs
        // If an ACK is seen and matches a seq entry, use it to compute RTT and reduce inflight estimate.
        if (tcp->ack) {
            __u32 ack = bpf_ntohl(tcp->ack_seq);
            // probe a small window for matching seq (MSS granularity)
            struct seq_key sk = {};
            sk.f = fk;
            __u32 probe_seq = ack - 1;
#pragma unroll
            for (int i = 0; i < 4; i++) {
                sk.seq = probe_seq - i;
                __u64 *ts_p = bpf_map_lookup_elem(&seq_ts, &sk);
                if (ts_p) {
                    __u64 rtt = now - *ts_p;
                    __sync_fetch_and_add(&fs->rtt_sum_ns, rtt);
                    __sync_fetch_and_add(&fs->rtt_count, 1);

                    // adjust inflight estimate by MSS approximation (1448)
                    __u64 dec = 1448;
                    if (fs->inflight_bytes > dec) fs->inflight_bytes -= dec;
                    else fs->inflight_bytes = 0;

                    bpf_map_delete_elem(&seq_ts, &sk);
                    break;
                }
            }
        }
    }

    return XDP_PASS;
}

SEC("xdp")
int xdp_tcp_metrics(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    // parse and update maps
    return parse_and_update(data, data_end);
}

char _license[] SEC("license") = "GPL";