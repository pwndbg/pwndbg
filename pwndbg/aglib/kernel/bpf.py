from __future__ import annotations

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory


def get_struct_bpf_prog() -> str:
    result = f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    result += """
    /* the enum types (probably) have been added to the kernel in decending order */
    enum bpf_prog_type {
        BPF_PROG_TYPE_UNSPEC,
        BPF_PROG_TYPE_SOCKET_FILTER,
        BPF_PROG_TYPE_KPROBE,
        BPF_PROG_TYPE_SCHED_CLS,
        BPF_PROG_TYPE_SCHED_ACT,
        BPF_PROG_TYPE_TRACEPOINT,
        BPF_PROG_TYPE_XDP,
        BPF_PROG_TYPE_PERF_EVENT,
        BPF_PROG_TYPE_CGROUP_SKB,
        BPF_PROG_TYPE_CGROUP_SOCK,
        BPF_PROG_TYPE_LWT_IN,
        BPF_PROG_TYPE_LWT_OUT,
        BPF_PROG_TYPE_LWT_XMIT,
        BPF_PROG_TYPE_SOCK_OPS,
        BPF_PROG_TYPE_SK_SKB,
        BPF_PROG_TYPE_CGROUP_DEVICE,
        BPF_PROG_TYPE_SK_MSG,
        BPF_PROG_TYPE_RAW_TRACEPOINT,
        BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
        BPF_PROG_TYPE_LWT_SEG6LOCAL,
        BPF_PROG_TYPE_LIRC_MODE2,
        BPF_PROG_TYPE_SK_REUSEPORT,
        BPF_PROG_TYPE_FLOW_DISSECTOR,
        BPF_PROG_TYPE_CGROUP_SYSCTL,
        BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
        BPF_PROG_TYPE_CGROUP_SOCKOPT,
        BPF_PROG_TYPE_TRACING,
        BPF_PROG_TYPE_STRUCT_OPS,
        BPF_PROG_TYPE_EXT,
        BPF_PROG_TYPE_LSM,
        BPF_PROG_TYPE_SK_LOOKUP,
        BPF_PROG_TYPE_SYSCALL, /* a program that can execute syscalls */
        BPF_PROG_TYPE_NETFILTER,
        __MAX_BPF_PROG_TYPE
    };
    enum bpf_attach_type {
        BPF_CGROUP_INET_INGRESS,
        BPF_CGROUP_INET_EGRESS,
        BPF_CGROUP_INET_SOCK_CREATE,
        BPF_CGROUP_SOCK_OPS,
        BPF_SK_SKB_STREAM_PARSER,
        BPF_SK_SKB_STREAM_VERDICT,
        BPF_CGROUP_DEVICE,
        BPF_SK_MSG_VERDICT,
        BPF_CGROUP_INET4_BIND,
        BPF_CGROUP_INET6_BIND,
        BPF_CGROUP_INET4_CONNECT,
        BPF_CGROUP_INET6_CONNECT,
        BPF_CGROUP_INET4_POST_BIND,
        BPF_CGROUP_INET6_POST_BIND,
        BPF_CGROUP_UDP4_SENDMSG,
        BPF_CGROUP_UDP6_SENDMSG,
        BPF_LIRC_MODE2,
        BPF_FLOW_DISSECTOR,
        BPF_CGROUP_SYSCTL,
        BPF_CGROUP_UDP4_RECVMSG,
        BPF_CGROUP_UDP6_RECVMSG,
        BPF_CGROUP_GETSOCKOPT,
        BPF_CGROUP_SETSOCKOPT,
        BPF_TRACE_RAW_TP,
        BPF_TRACE_FENTRY,
        BPF_TRACE_FEXIT,
        BPF_MODIFY_RETURN,
        BPF_LSM_MAC,
        BPF_TRACE_ITER,
        BPF_CGROUP_INET4_GETPEERNAME,
        BPF_CGROUP_INET6_GETPEERNAME,
        BPF_CGROUP_INET4_GETSOCKNAME,
        BPF_CGROUP_INET6_GETSOCKNAME,
        BPF_XDP_DEVMAP,
        BPF_CGROUP_INET_SOCK_RELEASE,
        BPF_XDP_CPUMAP,
        BPF_SK_LOOKUP,
        BPF_XDP,
        BPF_SK_SKB_VERDICT,
        BPF_SK_REUSEPORT_SELECT,
        BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
        BPF_PERF_EVENT,
        BPF_TRACE_KPROBE_MULTI,
        BPF_LSM_CGROUP,
        BPF_STRUCT_OPS,
        BPF_NETFILTER,
        BPF_TCX_INGRESS,
        BPF_TCX_EGRESS,
        BPF_TRACE_UPROBE_MULTI,
        BPF_CGROUP_UNIX_CONNECT,
        BPF_CGROUP_UNIX_SENDMSG,
        BPF_CGROUP_UNIX_RECVMSG,
        BPF_CGROUP_UNIX_GETPEERNAME,
        BPF_CGROUP_UNIX_GETSOCKNAME,
        BPF_NETKIT_PRIMARY,
        BPF_NETKIT_PEER,
        BPF_TRACE_KPROBE_SESSION,
        BPF_TRACE_UPROBE_SESSION,
        __MAX_BPF_ATTACH_TYPE
    };
    #define BPF_TAG_SIZE 8 // true for v5.0 - 6.17
    struct sock_filter {	/* Filter block */
        u16	code;   /* Actual filter code */
        u8	jt;	/* Jump true */
        u8	jf;	/* Jump false */
        u32	k;      /* Generic multiuse field */
    };
    struct sock_fprog_kern {
        u16			len;
        struct sock_filter	*filter;
    };
    struct bpf_prog {
        u16			pages;		/* Number of allocated pages */
        u16			fields;     /* bit fields */
        enum bpf_prog_type	type;		/* Type of BPF program */
        enum bpf_attach_type	expected_attach_type; /* For some prog types */
        u32			len;		/* Number of filter blocks */
        u32			jited_len;	/* Size of jited insns in bytes */
        u8			tag[BPF_TAG_SIZE];
#if KVERSION >= KERNEL_VERSION(5, 12, 0)
        void *stats; // bpf_prog_stats
        int 		*active;
        unsigned int		(*bpf_func)(void *ctx, void *insn);
#endif
        void	*aux;		/* Auxiliary fields */
        struct sock_fprog_kern *orig_prog;	/* Original BPF program */
#if KVERSION < KERNEL_VERSION(5, 12, 0)
        unsigned int		(*bpf_func)(void *ctx, void *insn);
#endif
        char insns[];
    };
    """
    return result


def get_struct_bpf_map() -> str:
    result = ""
    if "CONFIG_SECURITY" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_SECURITY\n"
    result += """
    enum bpf_map_type {
        BPF_MAP_TYPE_UNSPEC,
        BPF_MAP_TYPE_HASH,
        BPF_MAP_TYPE_ARRAY,
        BPF_MAP_TYPE_PROG_ARRAY,
        BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        BPF_MAP_TYPE_PERCPU_HASH,
        BPF_MAP_TYPE_PERCPU_ARRAY,
        BPF_MAP_TYPE_STACK_TRACE,
        BPF_MAP_TYPE_CGROUP_ARRAY,
        BPF_MAP_TYPE_LRU_HASH,
        BPF_MAP_TYPE_LRU_PERCPU_HASH,
        BPF_MAP_TYPE_LPM_TRIE,
        BPF_MAP_TYPE_ARRAY_OF_MAPS,
        BPF_MAP_TYPE_HASH_OF_MAPS,
        BPF_MAP_TYPE_DEVMAP,
        BPF_MAP_TYPE_SOCKMAP,
        BPF_MAP_TYPE_CPUMAP,
        BPF_MAP_TYPE_XSKMAP,
        BPF_MAP_TYPE_SOCKHASH,
        BPF_MAP_TYPE_CGROUP_STORAGE,
        BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
        BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
        BPF_MAP_TYPE_QUEUE,
        BPF_MAP_TYPE_STACK,
        BPF_MAP_TYPE_SK_STORAGE,
        BPF_MAP_TYPE_DEVMAP_HASH,
        BPF_MAP_TYPE_STRUCT_OPS,
        BPF_MAP_TYPE_RINGBUF,
        BPF_MAP_TYPE_INODE_STORAGE,
        BPF_MAP_TYPE_TASK_STORAGE,
        BPF_MAP_TYPE_BLOOM_FILTER,
        BPF_MAP_TYPE_USER_RINGBUF,
        BPF_MAP_TYPE_CGRP_STORAGE,
        BPF_MAP_TYPE_ARENA,
        __MAX_BPF_MAP_TYPE
    };
    """
    result += """
    struct bpf_map {
        const void *ops; // struct bpf_map_ops
        struct bpf_map *inner_map_meta;
#ifdef CONFIG_SECURITY
        void *security;
#endif
        enum bpf_map_type map_type;
        u32 key_size;
        u32 value_size;
        u32 max_entries;
        // char _pad[{padsz}];
    };
    struct bpf_array {
        struct bpf_map map;
        /* ignore the rest of the fields for now */
    };
    """
    return result


def get_bpf_struct_offsets(prog_idr: int, map_idr: int) -> int | None:
    xarray_pad_sz = None
    ptrsize = pwndbg.aglib.arch.ptrsize
    max_idr_sz = abs(map_idr - prog_idr)
    xa_node = None
    for i in range(0, max_idr_sz, ptrsize):
        xa_node = pwndbg.aglib.memory.read_pointer_width(prog_idr + i) & ~3  # remove tag
        if pwndbg.aglib.memory.is_kernel(xa_node):
            xarray_pad_sz = i
    if xarray_pad_sz:
        return xarray_pad_sz
    for i in range(0, max_idr_sz, ptrsize):
        xa_node = pwndbg.aglib.memory.read_pointer_width(map_idr + i) & ~3  # remove tag
        if pwndbg.aglib.memory.is_kernel(xa_node):
            xarray_pad_sz = i
    return xarray_pad_sz


@pwndbg.aglib.kernel.typeinfo_recovery("struct bpf_map", requires_kversion=True)
def recover_bpf_typeinfo() -> str:
    prog_idr = pwndbg.aglib.kernel.prog_idr()
    map_idr = pwndbg.aglib.kernel.map_idr()
    if not prog_idr or not map_idr:
        raise AssertionError("cannot find either prog_idr or map_idr")
    xarray_pad_sz = get_bpf_struct_offsets(int(prog_idr), int(map_idr))
    assert xarray_pad_sz, (
        "cannot find xa_head -- might be uninitialized (add a bpf prog/map first!)"
    )
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += f"""
    struct xarray {{
        char _xarray_pad[{xarray_pad_sz}];
        void *xa_head;
    }};
    """
    result += """
    struct idr {
        struct xarray idr_rt;
        unsigned int idr_base;
        unsigned int idr_next;
    };
    struct xa_node {
        unsigned char	shift;		/* Bits remaining in each slot */
        unsigned char	offset;		/* Slot offset in parent */
        unsigned char	count;		/* Total entry count */
        unsigned char	nr_values;	/* Value entry count */
        struct xa_node *parent;	/* NULL at top of tree */
        struct xarray	*array;		/* The array we belong to */
        union {
            struct list_head private_list;	/* For tree user */
            // struct rcu_head	rcu_head;	/* Used when freeing node */
        };
        void *slots[64]; // 16 or 64
        /* the rest is not relevant */
    };
    """
    result += get_struct_bpf_prog()
    result += get_struct_bpf_map()
    return result
