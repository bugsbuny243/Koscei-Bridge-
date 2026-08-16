// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — Linux BPF LSM enforcement prototype.
//
// This object is intentionally policy-map driven. A workload is never placed
// into prevention mode merely because this object loaded; the Go-side loader
// must verify hook attachment, artifact binding, and map population first.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct workload_gate {
    __u8 enabled;
    __u8 deny_exec;
    __u8 deny_file_write;
    __u8 deny_privilege;
};

struct artifact_digest {
    __u8 sha256[32];
};

// Key: cgroup v2 id for the supervised workload.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct workload_gate);
} workload_gates SEC(".maps");

// Evidence binding for the exact artifact approved by userspace before the
// cgroup gate is armed. The LSM program does not interpret the digest; the
// privileged loader must populate and verify it before enabling prevention.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct artifact_digest);
} artifact_bindings SEC(".maps");

static __always_inline struct workload_gate *current_gate(void)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    return bpf_map_lookup_elem(&workload_gates, &cgid);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(nodeshield_bprm_check, struct linux_binprm *bprm, int ret)
{
    struct workload_gate *gate;

    if (ret)
        return ret;

    gate = current_gate();
    if (!gate || !gate->enabled)
        return 0;

    if (gate->deny_exec)
        return -13; // -EACCES

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(nodeshield_file_open, struct file *file, int ret)
{
    struct workload_gate *gate;
    fmode_t mode;

    if (ret)
        return ret;

    gate = current_gate();
    if (!gate || !gate->enabled || !gate->deny_file_write)
        return 0;

    mode = BPF_CORE_READ(file, f_mode);
    if (mode & (FMODE_WRITE | FMODE_PWRITE))
        return -13; // -EACCES

    return 0;
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(nodeshield_task_fix_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    struct workload_gate *gate;

    if (ret)
        return ret;

    gate = current_gate();
    if (!gate || !gate->enabled)
        return 0;

    if (gate->deny_privilege)
        return -1; // -EPERM

    return 0;
}
