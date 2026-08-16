// SPDX-License-Identifier: GPL-2.0
// Koschei Node Shield — cgroup-scoped BPF LSM enforcement.
// BPF_LSM_CGROUP semantics: return 1 to allow and 0 to deny (EPERM).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef MAY_WRITE
#define MAY_WRITE 0x00000002
#endif
#ifndef SOCK_RAW
#define SOCK_RAW 3
#endif
#ifndef AF_PACKET
#define AF_PACKET 17
#endif

char LICENSE[] SEC("license") = "GPL";

struct workload_gate { __u8 enabled; __u8 deny_exec; __u8 deny_file_write; __u8 deny_privilege; __u8 deny_raw_socket; };
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

static __always_inline int allow_unless_write_denied(void)
{
    struct workload_gate *gate = current_gate();
    return !(gate && gate->enabled && gate->deny_file_write);
}

static __always_inline int allow_unless_privilege_denied(void)
{
    struct workload_gate *gate = current_gate();
    return !(gate && gate->enabled && gate->deny_privilege);
}

static __always_inline int raw_socket_denied(void)
{
    struct workload_gate *gate = current_gate();
    return gate && gate->enabled && gate->deny_raw_socket;
}

SEC("lsm_cgroup/bprm_check_security")
int BPF_PROG(nodeshield_bprm_check, struct linux_binprm *bprm)
{
    struct workload_gate *gate = current_gate();
    return !(gate && gate->enabled && gate->deny_exec);
}

// Actual I/O path: catches writes through descriptors opened before policy arm.
SEC("lsm_cgroup/file_permission")
int BPF_PROG(nodeshield_file_permission, struct file *file, int mask)
{
    if (!(mask & MAY_WRITE)) return 1;
    return allow_unless_write_denied();
}

// Pre-side-effect inode hooks: prevent create and truncate/attribute mutation
// before VFS changes become visible.
SEC("lsm_cgroup/inode_create")
int BPF_PROG(nodeshield_inode_create, struct inode *dir, struct dentry *dentry, umode_t mode)
{ return allow_unless_write_denied(); }

SEC("lsm_cgroup/inode_permission")
int BPF_PROG(nodeshield_inode_permission, struct inode *inode, int mask)
{
    if (!(mask & MAY_WRITE)) return 1;
    return allow_unless_write_denied();
}

SEC("lsm_cgroup/inode_setattr")
int BPF_PROG(nodeshield_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *attr)
{ return allow_unless_write_denied(); }

SEC("lsm_cgroup/task_fix_setuid")
int BPF_PROG(nodeshield_task_fix_setuid, struct cred *new, const struct cred *old, int flags)
{ return allow_unless_privilege_denied(); }

SEC("lsm_cgroup/task_fix_setgid")
int BPF_PROG(nodeshield_task_fix_setgid, struct cred *new, const struct cred *old, int flags)
{ return allow_unless_privilege_denied(); }

SEC("lsm_cgroup/task_fix_setgroups")
int BPF_PROG(nodeshield_task_fix_setgroups, struct cred *new, const struct cred *old)
{ return allow_unless_privilege_denied(); }

SEC("lsm_cgroup/capset")
int BPF_PROG(nodeshield_capset, struct cred *new, const struct cred *old,
             const kernel_cap_t *effective, const kernel_cap_t *inheritable,
             const kernel_cap_t *permitted)
{ return allow_unless_privilege_denied(); }

// Raw and packet sockets bypass destination-level TCP connect / UDP sendmsg
// authority. Node Shield therefore forbids creating them while an egress
// boundary is armed.
SEC("lsm_cgroup/socket_create")
int BPF_PROG(nodeshield_socket_create, int family, int type, int protocol, int kern)
{
    if (!raw_socket_denied()) return 1;
    if (family == AF_PACKET || type == SOCK_RAW) return 0;
    return 1;
}

// A workload may have opened a raw socket before freeze+arm. Re-check the
// actual socket at send time so pre-opened descriptors cannot bypass policy.
SEC("lsm_cgroup/socket_sendmsg")
int BPF_PROG(nodeshield_socket_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
    if (!raw_socket_denied() || !sock) return 1;
    if (sock->type == SOCK_RAW) return 0;
    if (sock->sk && sock->sk->__sk_common.skc_family == AF_PACKET) return 0;
    return 1;
}
