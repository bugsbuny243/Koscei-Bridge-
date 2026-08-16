// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — cgroup socket connect enforcement prototype.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct endpoint4 {
    __u32 addr;
    __u16 port;
    __u16 pad;
};

struct endpoint_key4 {
    __u64 cgroup_id;
    struct endpoint4 endpoint;
};

// Workloads appear in this map only after userspace binds the runtime policy
// to the approved artifact identity.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} protected_cgroups SEC(".maps");

// Exact IPv4 endpoint allowlist. DNS names are resolved and pinned by the
// userspace policy compiler; the kernel program never trusts mutable hostname
// strings.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct endpoint_key4);
    __type(value, __u8);
} allowed_endpoints4 SEC(".maps");

SEC("cgroup/connect4")
int nodeshield_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *protected;
    __u8 *allowed;
    struct endpoint_key4 key = {};

    protected = bpf_map_lookup_elem(&protected_cgroups, &cgid);
    if (!protected || !*protected)
        return 1;

    key.cgroup_id = cgid;
    key.endpoint.addr = ctx->user_ip4;
    key.endpoint.port = bpf_ntohs((__u16)ctx->user_port);

    allowed = bpf_map_lookup_elem(&allowed_endpoints4, &key);
    if (!allowed || !*allowed)
        return 0;

    return 1;
}
