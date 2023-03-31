#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    /* Check if packet is an IPv4 packet */
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        /* Count the packet */
        __sync_fetch_and_add(&packets, 1);
    }

    return XDP_PASS;
}

/* BPF map to hold the packet count */
struct bpf_map_def SEC("maps") packets_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(uint64_t),
    .max_entries = 1,
};

/* Exported variable for userspace to read packet count */
volatile uint64_t packets SEC("maps") = 0;


