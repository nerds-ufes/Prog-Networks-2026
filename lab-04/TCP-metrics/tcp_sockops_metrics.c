// tcp_sockops_metrics.c
//
// Compilação (kernel 6.x com clang-18):
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//   sudo clang-18 -O2 -g -target bpf -D__TARGET_ARCH_x86 -I. \
//     -c tcp_sockops_metrics.c -o tcp_sockops_metrics.o
//
// Carregar:
//   sudo bpftool prog load tcp_sockops_metrics.o /sys/fs/bpf/tcp_sockops type sockops
//
// Attach ao cgroup (cgroup v2):
//   sudo bpftool cgroup attach /sys/fs/cgroup sock_ops \
//     pinned /sys/fs/bpf/tcp_sockops multi
//
// Desanexar (cleanup):
//   sudo bpftool cgroup detach /sys/fs/cgroup sock_ops \
//     pinned /sys/fs/bpf/tcp_sockops multi

// vmlinux.h gerado via: bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
// Contém todos os tipos e enums do kernel atual — sem risco de divergência de valores.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

// AF_INET e AF_INET6 não são exportados pelo vmlinux.h — definição manual necessária.
#define AF_INET  2
#define AF_INET6 10

// -----------------------------------------------------------------
// CORREÇÃO BUG #2: Removidos os #define manuais com valores errados.
// Os valores reais do kernel 6.8 são (definidos em vmlinux.h):
//   BPF_SOCK_OPS_VOID                    0
//   BPF_SOCK_OPS_TIMEOUT_INIT            1
//   BPF_SOCK_OPS_RWND_INIT               2
//   BPF_SOCK_OPS_TCP_CONNECT_CB          3
//   BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB   4
//   BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB  5
//   BPF_SOCK_OPS_NEEDS_ECN               6
//   BPF_SOCK_OPS_BASE_RTT                7
//   BPF_SOCK_OPS_RTO_CB                  8
//   BPF_SOCK_OPS_RETRANS_CB              9
//   BPF_SOCK_OPS_STATE_CB                10
//   BPF_SOCK_OPS_TCP_LISTEN_CB           11
//   BPF_SOCK_OPS_RTT_CB                  13  (kernel 6.x)
// -----------------------------------------------------------------

// -----------------------------------------------------------------
// Estruturas de chave e valor do mapa
// -----------------------------------------------------------------

// MELHORIA DICA #3: Suporte a IPv4 e IPv6 com union.
// Nomes prefixados com tcp_ para evitar conflito com tipos do vmlinux.h
// (flow_key e flow_stats já existem no kernel).
struct tcp_flow_key {
    union {
        __u32 src_ip4;
        __u32 src_ip6[4];
    };
    union {
        __u32 dst_ip4;
        __u32 dst_ip6[4];
    };
    __u16 src_port;
    __u16 dst_port;
    __u8  family;       // AF_INET ou AF_INET6
    __u8  pad[3];       // alinhamento explícito
};

struct tcp_flow_stats {
    __u64 srtt_us;
    __u32 cwnd;         // cwnd atual (última leitura no RTT_CB)
    __u32 cwnd_max;     // cwnd máximo observado na conexão
    __u32 ssthresh;
    __u32 pkts_out;     // segmentos em voo no momento do RTT_CB
    __u64 bytes_acked;
    __u64 retransmissions;
    __u64 last_bytes_acked;
    __u64 last_segs_out;
    __u64 timestamp_ns;
};

// -----------------------------------------------------------------
// Mapa principal — por conexão TCP (IPv4 + IPv6)
// -----------------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key,   struct tcp_flow_key);
    __type(value, struct tcp_flow_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} tcp_flows SEC(".maps");

// -----------------------------------------------------------------
// Helpers internos
// -----------------------------------------------------------------

// Preenche tcp_flow_key a partir do contexto sock_ops.
//
// IMPORTANTE: O verifier do eBPF proíbe aritmética em ponteiros de contexto
// (ctx). Por isso cada campo de skops é lido com acesso direto de offset
// constante — nunca via ponteiro intermediário modificado (p += offset).
// Os campos local_ip6/remote_ip6 são arrays no ctx e devem ser lidos
// elemento a elemento com BPF_CORE_READ ou acesso indexado direto.
static __always_inline int build_flow_key(struct bpf_sock_ops *skops,
                                           struct tcp_flow_key *key)
{
    __builtin_memset(key, 0, sizeof(*key));

    __u32 family = skops->family;

    if (family == AF_INET) {
        key->src_ip4  = skops->local_ip4;
        key->dst_ip4  = skops->remote_ip4;
        key->family   = AF_INET;
        // local_port está em host byte order; remote_port em network byte order
        key->src_port = bpf_ntohs((__u16)skops->local_port);
        // remote_port: porta nos 16 bits ALTOS em network byte order.
        // Assimetria intencional do kernel — oposto de local_port.
        key->dst_port = bpf_ntohs((__u16)(skops->remote_port >> 16));

    } else if (family == AF_INET6) {
        // Leitura elemento a elemento com offset constante — obrigatório
        // para satisfazer o verifier (sem ponteiro de ctx modificado).
        key->src_ip6[0] = BPF_CORE_READ(skops, local_ip6[0]);
        key->src_ip6[1] = BPF_CORE_READ(skops, local_ip6[1]);
        key->src_ip6[2] = BPF_CORE_READ(skops, local_ip6[2]);
        key->src_ip6[3] = BPF_CORE_READ(skops, local_ip6[3]);

        key->dst_ip6[0] = BPF_CORE_READ(skops, remote_ip6[0]);
        key->dst_ip6[1] = BPF_CORE_READ(skops, remote_ip6[1]);
        key->dst_ip6[2] = BPF_CORE_READ(skops, remote_ip6[2]);
        key->dst_ip6[3] = BPF_CORE_READ(skops, remote_ip6[3]);

        key->family   = AF_INET6;
        key->src_port = bpf_ntohs((__u16)skops->local_port);
        key->dst_port = bpf_ntohs((__u16)(skops->remote_port >> 16));

    } else {
        return -1;
    }

    return 0;
}

// -----------------------------------------------------------------
// Programa principal
// -----------------------------------------------------------------
SEC("sockops")
int tcp_metrics(struct bpf_sock_ops *skops)
{
    // Apenas IPv4 e IPv6
    if (skops->family != AF_INET && skops->family != AF_INET6)
        return 0;

    // -----------------------------------------------------------------
    // MELHORIA DICA #1: Ativar callbacks RTT e STATE no momento do
    // estabelecimento da conexão (ativa ou passiva). Sem isso o kernel
    // nunca chama RTT_CB nem STATE_CB — o código original nunca
    // coletaria métricas de RTT ou mudanças de estado.
    // -----------------------------------------------------------------
    if (skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_ops_cb_flags_set(skops,
            BPF_SOCK_OPS_RTT_CB_FLAG     |
            BPF_SOCK_OPS_STATE_CB_FLAG   |
            BPF_SOCK_OPS_RETRANS_CB_FLAG |
            BPF_SOCK_OPS_RTO_CB_FLAG);   // captura cwnd no momento do RTO
    }

    // Filtra apenas os eventos que nos interessam
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB  &&
        skops->op != BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB &&
        skops->op != BPF_SOCK_OPS_RTT_CB                 &&
        skops->op != BPF_SOCK_OPS_RTO_CB                 &&
        skops->op != BPF_SOCK_OPS_STATE_CB               &&
        skops->op != BPF_SOCK_OPS_RETRANS_CB)
        return 0;

    // Monta a chave de fluxo
    struct tcp_flow_key key;
    if (build_flow_key(skops, &key) < 0)
        return 0;

    // -----------------------------------------------------------------
    // MELHORIA DICA #2: Cleanup ao fechar a conexão — evita saturação
    // do mapa. Sem isso as 16 384 entradas se esgotam em produção.
    // -----------------------------------------------------------------
    if (skops->op == BPF_SOCK_OPS_STATE_CB) {
        // args[1] contém o novo estado TCP
        if (skops->args[1] == BPF_TCP_CLOSE ||
            skops->args[1] == BPF_TCP_CLOSE_WAIT) {
            bpf_map_delete_elem(&tcp_flows, &key);
            return 0;
        }
    }

    // Lookup ou criação da entrada
    struct tcp_flow_stats *stats;
    struct tcp_flow_stats  zero = {};

    stats = bpf_map_lookup_elem(&tcp_flows, &key);
    if (!stats) {
        // AVISO #1: BPF_NOEXIST evita sobrescrever entrada criada
        // por outro CPU entre o lookup e o update.
        bpf_map_update_elem(&tcp_flows, &key, &zero, BPF_NOEXIST);
        stats = bpf_map_lookup_elem(&tcp_flows, &key);
        if (!stats)
            return 0;
    }

    // Timestamp sempre atualizado
    stats->timestamp_ns = bpf_ktime_get_ns();

    // -----------------------------------------------------------------
    // Atualiza métricas de acordo com o tipo de evento
    // -----------------------------------------------------------------
    if (skops->op == BPF_SOCK_OPS_RTT_CB ||
        skops->op == BPF_SOCK_OPS_RTO_CB ||
        skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        skops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {

        // srtt_us: kernel armazena *8, corrigimos aqui
        stats->srtt_us     = skops->srtt_us >> 3;
        stats->ssthresh    = skops->snd_ssthresh;
        stats->bytes_acked = skops->bytes_acked;
        stats->pkts_out    = skops->packets_out;

        // Atualiza cwnd e rastreia o pico histórico
        __u32 cwnd = skops->snd_cwnd;
        stats->cwnd = cwnd;
        if (cwnd > stats->cwnd_max)
            stats->cwnd_max = cwnd;

        // Estimativa indireta de retransmissões (fallback)
        __u64 segs_out    = skops->segs_out;
        __u64 bytes_acked = skops->bytes_acked;

        if (stats->last_segs_out > 0 &&
            segs_out > stats->last_segs_out &&
            bytes_acked == stats->last_bytes_acked) {
            __sync_fetch_and_add(&stats->retransmissions, 1);
        }

        stats->last_segs_out    = segs_out;
        stats->last_bytes_acked = bytes_acked;
    }

    // Contagem direta de retransmissões + captura cwnd no momento da perda
    if (skops->op == BPF_SOCK_OPS_RETRANS_CB) {
        __sync_fetch_and_add(&stats->retransmissions, 1);
        // cwnd cai após retransmissão — registra o valor pós-queda
        stats->cwnd = skops->snd_cwnd;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";