// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — cgroup-scoped BPF LSM enforcement.
//
// These programs use BPF_LSM_CGROUP attachment. The privileged loader attaches
// them to the exact verified cgroup file descriptor, so the policy applies to
// that cgroup and its descendants instead of installing one host-global LSM
// stack per workload.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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

// Per-loaded-workload policy. A cgroup-scoped LSM program only executes for
// the cgroup subtree it is attached to, so no cgroup-id lookup is required.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct workload_gate);
} workload_gate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct artifact_digest);
} artifact_binding_map SEC(".maps");

static __always_inline struct workload_gate *current_gate(void)
{
    __u32 zero = 0;
    return bpf_map_lookup_elem(&workload_gate_map, &zero);
}

static __always_inline int deny_privilege_if_armed(int ret)
{
    struct workload_gate *gate;
    if (ret)
        return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_privilege)
        return -1; // -EPERM
    return 0;
}

SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(nodeshield_bprm_check, struct linux_binprm *bprm, int ret)
{
    struct workload_gate *gate;
    if (ret)
        return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_exec)
        return -13; // -EACCES
    return 0;
}

// file_permission is evaluated on actual I/O, including writes through a file
// descriptor opened before the policy was armed. This closes the pre-opened-FD
// bypass left by relying on file_open alone.
SEC("lsm_cgroup/file_permission")
int BPF_PROG(nodeshield_file_permission, struct file *file, int mask, int ret)
{
    struct workload_gate *gate;
    if (ret)
        return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_file_write && (mask & MAY_WRITE))
        return -13; // -EACCES
    return 0;
}

SEC("lsm_cgroup/task_fix_setuid")
int BPF_PROG(nodeshield_task_fix_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    return deny_privilege_if_armed(ret);
}

SEC("lsm_cgroup/task_fix_setgid")
int BPF_PROG(nodeshield_task_fix_setgid, struct cred *new, const struct cred *old, int flags, int ret)
{
    return deny_privilege_if_armed(ret);
}

SEC("lsm_cgroup/task_fix_setgroups")
int BPF_PROG(nodeshield_task_fix_setgroups, struct cred *new, const struct cred *old, int ret)
{
    return deny_privilege_if_armed(ret);
}

SEC("lsm_cgroup/capset")
int BPF_PROG(nodeshield_capset, struct cred *new, const struct cred *old,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted, int ret)
{
    return deny_privilege_if_armed(ret);
}
