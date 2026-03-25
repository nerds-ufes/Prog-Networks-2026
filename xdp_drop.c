#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/*
 * XDP program to drop ICMP packets.
 * 
 * Logic:
 * 1. Parse Ethernet Header
 * 2. Check for IPv4 (ETH_P_IP)
 * 3. Parse IP Header
 * 4. Check for ICMP (IPPROTO_ICMP)
 * 5. Drop if ICMP, Pass otherwise. <<--
 *
*/

/*
 * Map to count dropped packets.
 * Type: Array
 * Key: 0 (single counter)
 * Value: uint64_t (counter)
*/
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} packet_count_map SEC(".maps");

SEC("prog")
int xdp_drop_icmp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 1. Ethernet Header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // 2. Check for IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 3. IP Header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // 4. Check for ICMP
    if (ip->protocol == IPPROTO_ICMP) {
        __u32 key = 0;
        __u64 *value = bpf_map_lookup_elem(&packet_count_map, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }        
        // bpf_printk("Dropping ICMP packet\n"); // Optional logging
        return XDP_DROP;
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
