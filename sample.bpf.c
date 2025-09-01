// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP 0x0800
// Index 0 for ingress, Index 1 for egress.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} traffic_stats SEC(".maps");

static __always_inline void update_stats(u32 key, u64 len)
{
    u64 *byte_count;
    byte_count = bpf_map_lookup_elem(&traffic_stats, &key);
    if (byte_count)
    {
        __sync_fetch_and_add(byte_count, len);
    }
}

SEC("tc")
int handle_ingress(struct __sk_buff *skb)
{
    const u32 key = 0;
    update_stats(key, skb->len);

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Boundary check for the Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return TC_ACT_OK;
    }
    const __be32 target_ip = bpf_htonl(0x0a2a0005);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + sizeof(*eth);
    if ((void *)ip_header + sizeof(*ip_header) > data_end)
    {
        return TC_ACT_OK;
    }

    __be32 source_ip_addr = ip_header->saddr;
    __be32 dest_ip_addr = ip_header->daddr;
    if (source_ip_addr == target_ip || dest_ip_addr == target_ip)
    {
        bpf_printk("Ingress match nginx: source %pI4, DST: %pI4\n", &source_ip_addr, &dest_ip_addr);
        bpf_printk("Interface index ingress: %d\n", skb->ifindex);
        bpf_printk("Packet length ingress: %d\n", skb->len);
        // bpf_printk("time stamp for packet ingress %llu\n", skb->tstamp);
    }
    return TC_ACT_OK;
}

SEC("tc")
int handle_egress(struct __sk_buff *skb)
{
    const u32 key = 1;
    update_stats(key, skb->len);
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // Boundary check for the Ethernet header.
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    struct iphdr *ip_header = data + sizeof(*eth);
    if ((void *)ip_header + sizeof(*ip_header) > data_end)
    {
        return TC_ACT_OK;
    }

    __be32 source_ip_addr = ip_header->saddr;
    __be32 dest_ip_addr = ip_header->daddr;
    const __be32 target_ip = bpf_htonl(0x0a2a0005);

    if (source_ip_addr == target_ip || dest_ip_addr == target_ip)
    {
        bpf_printk("Egress nginx: source %pI4, DST: %pI4\n", &source_ip_addr, &dest_ip_addr);
        bpf_printk(" Interface index egress: %d\n", skb->ifindex);
        bpf_printk(" Packet length egress: %d\n", skb->len);
        // bpf_printk("time stamp for packet egress %llu\n", skb->tstamp);
    }

    return TC_ACT_OK;
}
SEC("license")
const char __license[] = "GPL";