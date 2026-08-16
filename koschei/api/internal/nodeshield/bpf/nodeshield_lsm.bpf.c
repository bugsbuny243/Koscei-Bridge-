// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — cgroup-scoped BPF LSM enforcement.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif

char LICENSE[] SEC("license") = "GPL";

struct workload_gate { __u8 enabled; __u8 deny_exec; __u8 deny_file_write; __u8 deny_privilege; };
struct artifact_digest { __u8 sha256[32]; };

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

static __always_inline int deny_write_if_armed(int ret)
{
    struct workload_gate *gate;
    if (ret) return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_file_write) return -13;
    return 0;
}

static __always_inline int deny_privilege_if_armed(int ret)
{
    struct workload_gate *gate;
    if (ret) return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_privilege) return -1;
    return 0;
}

SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(nodeshield_bprm_check, struct linux_binprm *bprm, int ret)
{
    struct workload_gate *gate;
    if (ret) return ret;
    gate = current_gate();
    if (gate && gate->enabled && gate->deny_exec) return -13;
    return 0;
}

// Actual I/O path: catches writes through descriptors opened before policy arm.
SEC("lsm_cgroup/file_permission")
int BPF_PROG(nodeshield_file_permission, struct file *file, int mask, int ret)
{
    if (!(mask & MAY_WRITE)) return ret;
    return deny_write_if_armed(ret);
}

// Pre-side-effect inode hooks: prevent create and truncate/attribute mutation
// before VFS changes become visible.
SEC("lsm_cgroup/inode_create")
int BPF_PROG(nodeshield_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{ return deny_write_if_armed(ret); }

SEC("lsm_cgroup/inode_permission")
int BPF_PROG(nodeshield_inode_permission, struct inode *inode, int mask, int ret)
{
    if (!(mask & MAY_WRITE)) return ret;
    return deny_write_if_armed(ret);
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(nodeshield_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr, int ret)
{ return deny_write_if_armed(ret); }

SEC("lsm_cgroup/task_fix_setuid")
int BPF_PROG(nodeshield_task_fix_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{ return deny_privilege_if_armed(ret); }

SEC("lsm_cgroup/task_fix_setgid")
int BPF_PROG(nodeshield_task_fix_setgid, struct cred *new, const struct cred *old, int flags, int ret)
{ return deny_privilege_if_armed(ret); }

SEC("lsm_cgroup/task_fix_setgroups")
int BPF_PROG(nodeshield_task_fix_setgroups, struct cred *new, const struct cred *old, int ret)
{ return deny_privilege_if_armed(ret); }

SEC("lsm_cgroup/capset")
int BPF_PROG(nodeshield_capset, struct cred *new, const struct cred *old,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted, int ret)
{ return deny_privilege_if_armed(ret); }
