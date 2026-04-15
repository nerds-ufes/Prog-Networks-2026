/*
 * counter.bpf.c - Packet Counter XDP Program
 * Conta quantos pacotes passam por uma interface de rede em tempo real
 *
 * Fluxo:
 * 1. Pacote chega na NIC
 * 2. Kernel chama esta função XDP
 * 3. Incrementamos contador
 * 4. Retornamos XDP_PASS (deixar passar)
 * 
 */

#include <linux/bpf.h>      // Definições de BPF do kernel
#include <bpf/bpf_helpers.h> // Macros como SEC(), bpf_map_*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // Tipo: Array (fixo)
    __uint(max_entries, 1);              // 1 entrada apenas (um contador)
    __type(key, __u32);                  // Chave: unsigned int (4 bytes)
    __type(value, __u64);                // Valor: unsigned long (8 bytes)
} packet_counter SEC(".maps");
SEC("xdp")
int xdp_packet_counter(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *counter = bpf_map_lookup_elem(&packet_counter, &key);
    if (!counter) {
        return XDP_PASS;
    }
    __sync_fetch_and_add(counter, 1);   
    return XDP_PASS;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";