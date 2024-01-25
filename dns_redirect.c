#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

#define LOOPBACK 2130706433
#define DOCKERD_IP 2130706485
#define DOCKERD_PORT 41552
#define APP_CONTAINER_IP 3232266762
#define DNS_SERVER_IP 3232266753
#define DNS_SERVER_PORT 53
#define LOOPBACK_INTERFACE_INDEX 1
#define ETH0_INTERFACE_INDEX 2

struct l3_fields
{
    __u32 saddr;
    __u32 daddr;
};

struct l4_fields
{
    __u16 sport;
    __u16 dport;
};

struct udphdr
{
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

SEC("tc_eth0")
int dns_redirect_eth0_loopback(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip4h;
    struct l3_fields l3_original_fields;
    struct l3_fields l3_new_fields;
    struct l4_fields l4_original_fields;
    struct l4_fields l4_new_fields;

    // Checking if eth headers are incomplete
    if (data + sizeof(*eth) > data_end)
    {
        return TC_ACT_SHOT;
    }

    // Allowing IPV6 packets to passthrough without modification
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return TC_ACT_OK;
    }

    // Checking if IP headers are incomplete
    if (data + sizeof(*eth) + sizeof(*ip4h) > data_end)
    {
        return TC_ACT_SHOT;
    }
    ip4h = data + sizeof(*eth);
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_original_fields, sizeof(l3_original_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_original_fields, sizeof(l4_original_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new_fields, sizeof(l3_new_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_new_fields, sizeof(l4_new_fields));

// Check if this is a dns packet
if (ip4h->protocol == 17)
{
    if (data + sizeof(*eth) + sizeof(*ip4h) + sizeof(struct udphdr) > data_end)
    {
        return TC_ACT_SHOT;
    }

    struct udphdr *udph = data + sizeof(*eth) + sizeof(*ip4h);

    if (ntohl(ip4h->saddr) == DNS_SERVER_IP && ntohs(udph->source) == DNS_SERVER_PORT)
    {
        // Change sender address to ip of Dockerd dns resolver
        l3_new_fields.saddr = htonl(DOCKERD_IP);

        // Change destination address to LOOPBACK
        l3_new_fields.saddr = htonl(LOOPBACK);

        // Change source port to port 53
        l4_new_fields.sport = htons(DOCKERD_PORT);

        bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new_fields, sizeof(l3_new_fields), BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_new_fields, sizeof(l4_new_fields), BPF_F_RECOMPUTE_CSUM);

        // Correct the Checksum
        __u64 l3sum = bpf_csum_diff((__u32 *)&l3_original_fields, sizeof(l3_original_fields), (__u32 *)&l3_new_fields, sizeof(l3_new_fields), 0);
        __u64 l4sum = bpf_csum_diff((__u32 *)&l4_original_fields, sizeof(l4_original_fields), (__u32 *)&l4_new_fields, sizeof(l4_new_fields), l3sum);

        // update checksum
        int csumret = bpf_l4_csum_replace(skb, sizeof(*eth) + sizeof(*ip4h) + offsetof(struct udphdr, check), 0, l4sum, BPF_F_PSEUDO_HDR);
        csumret |= bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), 0, l3sum, 0);
        if (csumret)
        {
            return TC_ACT_SHOT;
        }

        // redirect packet to loopback interface
        __u32 ifindex = LOOPBACK_INTERFACE_INDEX;

        int ret = bpf_redirect_neigh(ifindex, NULL, 0, 0);
        return ret;
    }
}
    return TC_ACT_OK;
}

SEC("tc_loopback")
int dns_redirect_loopback_eth0(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip4h;
    struct l3_fields l3_original_fields;
    struct l3_fields l3_new_fields;
    struct l4_fields l4_original_fields;
    struct l4_fields l4_new_fields;

    // Checking if eth headers are incomplete
    if (data + sizeof(*eth) > data_end)
    {
        return TC_ACT_SHOT;
    }

    // Allowing IPV6 packets to passthrough without modification
    if (ntohs(eth->h_proto) != ETH_P_IP)
    {
        return TC_ACT_OK;
    }

    // Checking if Ip headers are incomplete
    if (data + sizeof(*eth) + sizeof(*ip4h) > data_end)
    {
        return TC_ACT_SHOT;
    }

    ip4h = data + sizeof(*eth);
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_original_fields, sizeof(l3_original_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_original_fields, sizeof(l4_original_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new_fields, sizeof(l3_new_fields));
    bpf_skb_load_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_new_fields, sizeof(l4_new_fields));

// Check if this is a dns packet
if (ip4h->protocol == 17)
{
    if (data + sizeof(*eth) + sizeof(*ip4h) + sizeof(struct udphdr) > data_end)
    {
        return TC_ACT_SHOT;
    }
    struct udphdr *udph = data + sizeof(*eth) + sizeof(*ip4h);

    if (ntohl(ip4h->daddr) == DOCKERD_IP && ntohs(udph->dest) == DOCKERD_PORT)
    {
        // Change sender address to ip of container
        l3_new_fields.saddr = htonl(APP_CONTAINER_IP);

        // Change destination address to ip of dns server
        l3_new_fields.daddr = htonl(DNS_SERVER_IP);

        // Change destination port to proxy port
        l4_new_fields.dport = htons(DNS_SERVER_PORT);

        bpf_skb_store_bytes(skb, sizeof(*eth) + offsetof(struct iphdr, saddr), &l3_new_fields, sizeof(l3_new_fields), BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, sizeof(*eth) + sizeof(*ip4h), &l4_new_fields, sizeof(l4_new_fields), BPF_F_RECOMPUTE_CSUM);

        // Correct the Checksum
        __u32 l3sum = bpf_csum_diff((__u32 *)&l3_original_fields, sizeof(l3_original_fields), (__u32 *)&l3_new_fields, sizeof(l3_new_fields), 0);
        __u64 l4sum = bpf_csum_diff((__u32 *)&l4_original_fields, sizeof(l4_original_fields), (__u32 *)&l4_new_fields, sizeof(l4_new_fields), l3sum);

        // update checksum
        int csumret = bpf_l4_csum_replace(skb, sizeof(*eth) + sizeof(*ip4h) + offsetof(struct udphdr, check), 0, l4sum, BPF_F_PSEUDO_HDR);
        csumret |= bpf_l3_csum_replace(skb, sizeof(*eth) + offsetof(struct iphdr, check), 0, l3sum, 0);
        if (csumret)
        {
            return TC_ACT_SHOT;
        }

        // redirect packet to eth0 interface
        __u32 ifindex = ETH0_INTERFACE_INDEX;

        int ret = bpf_redirect_neigh(ifindex, NULL, 0, 0);
        return ret;
    }
}
    return TC_ACT_OK;
}
