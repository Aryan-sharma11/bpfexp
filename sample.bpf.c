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

enum pkt_direction
{
    DIR_INGRESS = 0,
    DIR_EGRESS = 1,
};
struct map_key
{
    __u32 ip;
    __u8 direction;
} packet_key;
struct map_val
{
    __u64 timestamp_ns;
    __u64 pkt_len_kb;
    __u64 pkt_len_bytes;

} packet_val;

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2);
    __type(key, packet_key);
    __type(value, packet_val);
} pkt_info SEC(".maps");

// struct
// {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 2);
//     __type(key, );
//     __type(value, u64);
// } pkt_rules SEC(".maps");

// Index 0 for ingress, Index 1 for egress.
struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} traffic_stats SEC(".maps");

static __always_inline void
update_stats(u32 key, u64 len)
{
    u64 *byte_count;
    byte_count = bpf_map_lookup_elem(&traffic_stats, &key);
    if (byte_count)
    {
        __sync_fetch_and_add(byte_count, len);
    }
}

SEC("tc")
int handle_ingress(struct __sk_bu)
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
    const __be32 target_ip = bpf_htonl(0x0a2a000f);

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
    if (dest_ip_addr == target_ip)
    {
        bpf_printk("Ingress match nginx: source %pI4, DST: %pI4, InterfaceIndex %d\n", &source_ip_addr, &dest_ip_addr, skb->ifindex);
        bpf_printk("Packet length ingress: %d\n", skb->len);

        // bpf_printk("Interface index ingress: %d\n", skb->ifindex);
        // bpf_printk("Packet length ingress: %d\n", skb->len);
        struct map_key key1 = {};
        key1.ip = source_ip_addr;     // or ip->daddr depending on direction
        key1.direction = DIR_INGRESS; // or DIR_EGRESS depending on hook

        struct map_val *val = bpf_map_lookup_elem(&pkt_info, &key1);
        if (!val)
        {
            struct map_val new_val = {};
            new_val.timestamp_ns = bpf_ktime_get_ns();
            __u64 pkt_len = skb->len;
            new_val.pkt_len_bytes = pkt_len;
            if (new_val.pkt_len_bytes >= 1024)
            {
                new_val.pkt_len_kb += new_val.pkt_len_bytes / 1024;
                new_val.pkt_len_bytes = new_val.pkt_len_bytes % 1024;
            }
            bpf_map_update_elem(&pkt_info, &key1, &new_val, BPF_ANY);
            bpf_printk("Initialized packet length bytes Ingress: %llu, KB: %llu\n", new_val.pkt_len_bytes, new_val.pkt_len_kb);
        }
        else
        {
            val->timestamp_ns = bpf_ktime_get_ns();
            val->pkt_len_bytes += skb->len;
            if (val->pkt_len_bytes >= 1024)
            {
                val->pkt_len_kb += val->pkt_len_bytes / 1024;
                val->pkt_len_bytes = val->pkt_len_bytes % 1024;
            }
            bpf_printk("Updated packet length bytes Ingress: %llu, KB: %llu\n", val->pkt_len_bytes, val->pkt_len_kb);
            bpf_map_update_elem(&pkt_info, &key1, val, BPF_ANY);
        }
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
    const __be32 target_ip = bpf_htonl(0x0a2a000f);

    if (source_ip_addr == target_ip)
    {
        bpf_printk("Egress nginx: source %pI4, DST: %pI4 , Ifindex=%d\n", &source_ip_addr, &dest_ip_addr, skb->ifindex);
        bpf_printk("Packet length egress: %d skbhash=%u, skbmark=%u \n", skb->len, skb->hash, skb->mark);

        struct map_key key1 = {};
        key1.ip = source_ip_addr;    // or ip->daddr depending on direction
        key1.direction = DIR_EGRESS; // or DIR_EGRESS depending on hook

        struct map_val *val = bpf_map_lookup_elem(&pkt_info, &key1);
        if (!val)
        {
            struct map_val new_val = {};
            new_val.timestamp_ns = bpf_ktime_get_ns();
            __u64 pkt_len = skb->len;
            new_val.pkt_len_bytes = pkt_len;
            if (new_val.pkt_len_bytes >= 1024)
            {
                new_val.pkt_len_kb += new_val.pkt_len_bytes / 1024;
                new_val.pkt_len_bytes = new_val.pkt_len_bytes % 1024;
            }
            bpf_map_update_elem(&pkt_info, &key1, &new_val, BPF_ANY);
            bpf_printk("Initialized packet length bytes Egress: %llu, KB: %llu\n", new_val.pkt_len_bytes, new_val.pkt_len_kb);
        }
        else
        {
            val->timestamp_ns = bpf_ktime_get_ns();
            val->pkt_len_bytes += skb->len;
            if (val->pkt_len_bytes >= 1024)
            {
                val->pkt_len_kb += val->pkt_len_bytes / 1024;
                val->pkt_len_bytes = val->pkt_len_bytes % 1024;
            }
            bpf_printk("Updated packet length bytes Egress: %llu, KB: %llu\n", val->pkt_len_bytes, val->pkt_len_kb);
            bpf_map_update_elem(&pkt_info, &key1, val, BPF_ANY);
        }
        // bpf_printk("time stamp for packet egress %llu\n", skb->tstamp);
    }

    return TC_ACT_OK;
}
SEC("license")
const char __license[] = "GPL";