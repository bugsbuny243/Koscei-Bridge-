// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — cgroup socket-connect enforcement.
//
// The programs are attached to the exact verified workload cgroup. Cgroup BPF
// attachment is hierarchical, so descendants remain covered without relying on
// an exact current-cgroup-id map lookup.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct endpoint4 {
    __u32 addr;
    __u16 port;
    __u16 pad;
};

struct endpoint6 {
    __u32 addr[4];
    __u16 port;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} network_gate SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct endpoint4);
    __type(value, __u8);
} allowed_endpoints4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct endpoint6);
    __type(value, __u8);
} allowed_endpoints6 SEC(".maps");

static __always_inline int network_protected(void)
{
    __u32 zero = 0;
    __u8 *enabled = bpf_map_lookup_elem(&network_gate, &zero);
    return enabled && *enabled;
}

SEC("cgroup/connect4")
int nodeshield_connect4(struct bpf_sock_addr *ctx)
{
    __u8 *allowed;
    struct endpoint4 key = {};

    if (!network_protected())
        return 1;

    key.addr = bpf_ntohl(ctx->user_ip4);
    key.port = bpf_ntohs((__u16)ctx->user_port);
    allowed = bpf_map_lookup_elem(&allowed_endpoints4, &key);
    return allowed && *allowed;
}

SEC("cgroup/connect6")
int nodeshield_connect6(struct bpf_sock_addr *ctx)
{
    __u8 *allowed;
    struct endpoint6 key = {};

    if (!network_protected())
        return 1;

    key.addr[0] = bpf_ntohl(ctx->user_ip6[0]);
    key.addr[1] = bpf_ntohl(ctx->user_ip6[1]);
    key.addr[2] = bpf_ntohl(ctx->user_ip6[2]);
    key.addr[3] = bpf_ntohl(ctx->user_ip6[3]);
    key.port = bpf_ntohs((__u16)ctx->user_port);
    allowed = bpf_map_lookup_elem(&allowed_endpoints6, &key);
    return allowed && *allowed;
}
