// SPDX-License-Identifier: GPL-2.0
// Compile-only type surface for non-privileged Node Shield BPF CI.
//
// SECURITY NOTE: this file is NOT a CO-RE runtime ABI source and MUST NOT be
// used by the privileged kernel proof. The live proof always generates
// bpf/vmlinux.h from the target host's /sys/kernel/btf/vmlinux. This header only
// lets ordinary CI compile the BPF C sources and catch syntax/section/symbol
// errors when host BTF is unavailable.
#ifndef KOSCHEI_NODESHIELD_CI_VMLINUX_H
#define KOSCHEI_NODESHIELD_CI_VMLINUX_H

typedef unsigned char __u8;
typedef signed char __s8;
typedef unsigned short __u16;
typedef signed short __s16;
typedef unsigned int __u32;
typedef signed int __s32;
typedef unsigned long long __u64;
typedef signed long long __s64;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;
typedef unsigned short umode_t;

typedef struct { __u32 cap[2]; } kernel_cap_t;

struct linux_binprm;
struct file;
struct inode;
struct dentry;
struct cred;
struct mnt_idmap;
struct iattr;
struct msghdr;

// Minimal compile-only network object fields referenced by the LSM source.
struct sock_common { __u16 skc_family; };
struct sock { struct sock_common __sk_common; };
struct socket { int type; struct sock *sk; };

// Fields referenced by cgroup/connect* and cgroup/sendmsg* programs.
struct bpf_sock_addr {
    __u32 user_family;
    __u32 user_ip4;
    __u32 user_ip6[4];
    __u32 user_port;
    __u32 family;
    __u32 type;
    __u32 protocol;
    __u32 msg_src_ip4;
    __u32 msg_src_ip6[4];
};

#endif
