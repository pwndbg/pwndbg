from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo


def get_stack_offset(tasks: List[int]) -> int:
    ptrsize = pwndbg.aglib.arch.ptrsize
    for i in range(0x10):
        for task in tasks:
            a = pwndbg.aglib.memory.read_pointer_width(task + i * ptrsize)
            b = pwndbg.aglib.memory.read_pointer_width(task + (i + 1) * ptrsize)
            # for x64, the frist kernel pointer should be the stack
            # for aarch64, this might not be the case when CONFIG_SHADOW_CALL_STACK=y
            # see the definitions of task_struct and thread_info
            if pwndbg.aglib.memory.is_kernel(a) and not pwndbg.aglib.memory.is_kernel(b):
                return i * ptrsize
    return 0  # fine if stack not found, we can continue with the task_struct recovery


"""
    struct list_head tasks;
#ifdef CONFIG_SMP
    struct plist_node pushable_tasks; // 5 ptr size
    struct rb_node pushable_dl_tasks; // 3 ptr size
#endif

    struct mm_struct *mm; // Nullable
    struct mm_struct *active_mm;
"""


def get_tasks_offset(mm_offset: int) -> Tuple[List[int], int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    tasks_offset = mm_offset - ptrsize * 2
    if "CONFIG_SMP" in pwndbg.aglib.kernel.kconfig():
        tasks_offset -= ptrsize * 8
    tasks = None
    for i in range(pwndbg.aglib.kernel.nproc()):
        task = int(pwndbg.aglib.kernel.current_task(i))
        tasks = pwndbg.aglib.kernel.symbol.get_double_linked_list(task + tasks_offset)
        if tasks is not None:
            break
    assert tasks, (
        f"cannot find the tasks double linked list: (task: {hex(task)}, mm_offset: {hex(mm_offset)})"
    )
    tasks = [task - tasks_offset for task in tasks]
    return tasks, tasks_offset


def get_mm_offset(task: int) -> int:
    mm_offset = None
    ptrsize = pwndbg.aglib.arch.ptrsize
    for i in range(0x200):
        off = i * ptrsize
        try:
            val = pwndbg.aglib.memory.read_pointer_width(task + off)
            cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(val)
            if "mm_struct" == cache.name:
                mm_offset = off
                break
        except Exception:
            pass
    assert mm_offset, (
        f"cound not find the offset of task_struct->mm: (task: {hex(task)}, mm_offset: {hex(mm_offset)})"
    )
    try:
        mm_active = pwndbg.aglib.memory.read_pointer_width(task + mm_offset + ptrsize)
        cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(mm_active)
        assert cache.name == "mm_struct"
    except Exception:
        # we actually found active_mm instead
        mm_offset -= ptrsize
    return mm_offset


def get_mm_struct(tasks: List[int], mm_offset: int) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    pgd_offset = None
    match pwndbg.aglib.arch.name:
        case "x86-64":
            reg = "cr3"
        case "aarch64":
            reg = "TTBR0_EL1"
        case _:
            raise NotImplementedError()
    mask = pwndbg.aglib.kernel.arch_paginginfo().PAGE_ENTRY_MASK
    pgd_virt = pwndbg.aglib.kernel.phys_to_virt(pwndbg.aglib.regs.read_reg(reg) & mask)
    current_tasks = [
        int(pwndbg.aglib.kernel.current_task(i)) for i in range(pwndbg.aglib.kernel.nproc())
    ]
    for task in tasks + current_tasks:
        mm = pwndbg.aglib.memory.read_pointer_width(task + mm_offset)
        if pwndbg.aglib.memory.is_kernel(mm):
            for i in range(0x100):
                if pwndbg.aglib.memory.read_pointer_width(mm + i * ptrsize) == pgd_virt:
                    pgd_offset = i * ptrsize
                    break
        active_mm = pwndbg.aglib.memory.read_pointer_width(task + mm_offset + ptrsize)
        if pwndbg.aglib.memory.is_kernel(active_mm):
            for i in range(0x100):
                if pwndbg.aglib.memory.read_pointer_width(active_mm + i * ptrsize) == pgd_virt:
                    pgd_offset = i * ptrsize
                    break
        if pgd_offset:
            break
    assert pgd_offset, f"cannot find the offset of mm_struct->pgd: (active_mm: {hex(active_mm)})"

    return f"""
    struct mm_struct {{
        char _pad1[{pgd_offset}];
        void *pgd;
        /* don't care about the rest */
    }};
    """


"""
    pid_t				pid;
    pid_t				tgid;

#ifdef CONFIG_STACKPROTECTOR
    /* Canary value for the -fstack-protector GCC feature: */
    unsigned long			stack_canary;
#endif
    /*
        * Pointers to the (original) parent process, youngest child, younger sibling,
        * older sibling, respectively.  (p->father can be replaced with
        * p->real_parent->pid)
        */

    /* Real parent process: */
    struct task_struct __rcu	*real_parent;

    /* Recipient of SIGCHLD, wait4() reports: */
    struct task_struct __rcu	*parent;

    /*
        * Children/sibling form the list of natural children:
        */
    struct list_head		children;
    struct list_head		sibling;
    struct task_struct		*group_leader;

    /*
        * 'ptraced' is the list of tasks this task is using ptrace() on.
        *
        * This includes both natural children and PTRACE_ATTACH targets.
        * 'ptrace_entry' is this task's link on the p->parent->ptraced list.
        */
    struct list_head		ptraced;
    struct list_head		ptrace_entry;

    /* PID/PID hash table linkage. */
    struct pid			*thread_pid;
    struct hlist_node		pid_links[PIDTYPE_MAX]; // PIDTYPE_MAX == 4
    struct list_head		thread_group; // < 6.7
    struct list_head		thread_node;
"""

ROOT_COMM = "swapper/"


def get_pid_offset(tasks: List[int], mm_offset: int, comm_offset: int) -> int:
    maxpid = 0x400000 if pwndbg.aglib.arch.ptrsize == 8 else 0x8000
    seen = set()
    for i in range(0x20):
        off = mm_offset + i * pwndbg.aglib.arch.ptrsize
        for task in tasks[1:]:
            try:
                a = pwndbg.aglib.memory.read(task + comm_offset, len(ROOT_COMM))
                if a.decode() == ROOT_COMM:
                    continue
            except Exception:
                continue
            pid = pwndbg.aglib.memory.u32(task + off)
            tgid = pwndbg.aglib.memory.u32(task + off + 4)
            if not (0 < pid < maxpid and 0 < tgid < maxpid) or pid in seen:
                break
            seen.add(pid)
        else:
            return off
    raise AssertionError("cannot find the offset of task_struct->pid")


def get_thread_list_offset(pid_offset: int):
    # thread_group if <= 6.6 else thread_node
    off = pid_offset
    ptrsize = pwndbg.aglib.arch.ptrsize
    off += 21 * ptrsize
    if pwndbg.aglib.kernel.krelease() < (6, 7, 0):
        off += 2 * ptrsize
    if "CONFIG_STACKPROTECTOR" in pwndbg.aglib.kernel.kconfig():
        off += ptrsize
    return off


"""
    /* Process credentials: */

    /* Tracer's credentials at attach: */
    const struct cred __rcu *ptracer_cred;

    /* Objective and real subjective task credentials (COW): */
    const struct cred __rcu *real_cred;

    /* Effective (overridable) subjective task credentials (COW): */
    const struct cred __rcu *cred;

#ifdef CONFIG_KEYS
    /* Cached requested key. */
    struct key *cached_requested_key;
#endif

    /*
        * executable name, excluding path.
        *
        * - normally initialized setup_new_exec()
        * - access it with [gs]et_task_comm()
        * - lock it with task_lock()
        */
    char comm[TASK_COMM_LEN]; // usually TASK_COMM_LEN == 0x10

    struct nameidata *nameidata;

#ifdef CONFIG_SYSVIPC
    struct sysv_sem sysvsem;
    struct sysv_shm sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
    unsigned long last_switch_count;
    unsigned long last_switch_time;
#endif
    /* Filesystem information: */
    struct fs_struct *fs;

    /* Open file information: */
    struct files_struct *files;

#ifdef CONFIG_IO_URING
    struct io_uring_task *io_uring;
#endif

    /* Namespaces: */
    struct nsproxy *nsproxy;

    /* Signal handlers: */
    struct signal_struct *signal;
    struct sighand_struct __rcu *sighand;
    sigset_t blocked;
    sigset_t real_blocked;
"""

INIT_TASK = None


def get_comm_offset(tasks: List[int]) -> Tuple[int, int]:
    for task in tasks:
        off = 0
        for _ in range(0x300):
            try:
                s = pwndbg.aglib.memory.read(task + off, len(ROOT_COMM))
                if s.decode() == ROOT_COMM:
                    global INIT_TASK
                    INIT_TASK = task
                    return task, off
            except Exception:
                pass
            off += pwndbg.aglib.arch.ptrsize
    raise AssertionError("cannot find the offset of task_struct->comm")


def get_cred_struct_and_offset(tasks: List[int], comm_offset: int) -> Tuple[str, int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    cred_offset = None
    for task in tasks:
        off = comm_offset - ptrsize
        for _ in range(2):
            a = pwndbg.aglib.memory.read_pointer_width(task + off)
            b = pwndbg.aglib.memory.read_pointer_width(task + off - ptrsize)
            # cred == real_cred
            if pwndbg.aglib.memory.is_kernel(a) and a == b:
                cred_offset = off
                break
            off -= ptrsize
        if cred_offset is not None:
            break
    assert cred_offset, "cannot find the offset of task_struct->cred"
    cred = pwndbg.aglib.memory.read_pointer_width(INIT_TASK + cred_offset)
    off = None
    A = 0x30
    # find cap_permitted from INIT_TASK, the distance between uid and cap_permitted is 0x30
    for i in range(A // 4, A // 4 + 0x20):
        val = pwndbg.aglib.memory.u64(cred + i * 4)  # sizeof(kernel_cap_t) == 8 even for 32 bits
        if val == 0x000001FFFFFFFFFF:  # is this true for all 5.x and 6.x?
            off = i * 4 - A
    struct = f"""
    struct cred{{
        char _pad1[{off}];
        kuid_t uid;
        kgid_t gid;
        kuid_t suid;
        kgid_t sgid;
        kuid_t euid;
        kgid_t egid;
        kuid_t fsuid;
        kgid_t fsgid;
#if 0
        // TODO: `unsigned` might not be 32 bit?
        unsigned	securebits;	/* SUID-less security management */
        kernel_cap_t	cap_inheritable; /* caps our children can inherit */
        kernel_cap_t	cap_permitted;	/* caps we're permitted */
#endif
        /* don't care about the rest */
    }};
    """
    return struct, cred_offset


TASK_COMM_LEN = 0x10


def get_path_struct(mnt: int | None, dentry: int | None) -> str:
    # TODO: actually do something with the dentry
    result = ""
    result += """
    struct vfsmount {
        int a;
    };
    struct dentry {
        int a;
    };
    struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
    };
    """
    return result


def get_inode_struct(inode: int | None) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    kbase: int | None = pwndbg.aglib.kernel.kbase()
    off = 0x20
    if inode:
        for i in range(0x10):
            val = pwndbg.aglib.memory.read_pointer_width(inode + i * ptrsize)
            if kbase and kbase < val:
                off = i * ptrsize
                break
    return f"""
    struct inode {{
        char _pad[{off}];
        unsigned long i_ino;
    }};
    """


def get_file_struct(file: int | None) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    result = ""
    kversion: Tuple[int, ...] = pwndbg.aglib.kernel.krelease()
    kbase: int | None = pwndbg.aglib.kernel.kbase()
    if "CONFIG_SECURITY" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_SECURITY\n"
    result += """
    typedef unsigned int fmode_t;
    """
    mnt = dentry = inode = None
    off: int
    _result = ""
    if not file or kversion >= (6, 12):
        # find f_op
        off = "spinlock_t_size"
        if file:
            for i in range(1, 0x20):
                val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
                if kbase and val > kbase:
                    off = (i - 1) * ptrsize
                    break
        # this should work for the most recent versions
        _result = f"""
        struct file {{
            char _pad2[{off}];
            unsigned int f_mode;
            void* f_op;
            void *f_mapping;
            void *private_data;
            struct inode *f_inode;
            unsigned int f_flags;
            unsigned int f_iocb_flags;
            const struct cred *f_cred;
            /* --- cacheline 1 boundary (64 bytes) --- */
            struct path f_path;
            /* don't care about the rest */
        }};
        """
        if isinstance(off, int):
            off += 4
            off = (off // ptrsize) * ptrsize + (ptrsize if off % ptrsize else 0)
            mnt = pwndbg.aglib.memory.read_pointer_width(file + off + 4 * 2 + ptrsize * 5)
            dentry = pwndbg.aglib.memory.read_pointer_width(file + off + 4 * 2 + ptrsize * 6)
            inode = pwndbg.aglib.memory.read_pointer_width(file + off + ptrsize * 3)
    elif kversion >= (6, 5):
        # find the cache that contains the inode
        off = 0
        for i in range(2, 0x20):
            val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
            try:
                cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(val)
                if "inode" in cache.name:
                    off = (i - 2) * ptrsize
                    break
            except Exception:
                pass
        _result = f"""
        struct file {{
            union {{
                struct {{
                    char _pad1[PTR_SIZE * 2 + spinlock_t_size];
                    fmode_t f_mode;
                }};
                char _pad2[{off}];
            }};
            struct path f_path;
            struct inode *f_inode;
            void *f_op;
            u64 f_version;
#ifdef CONFIG_SECURITY
            void *f_security;
#endif
            void *private_data;
            /* don't care about the rest */
        }};
        """
        if off > 0:
            mnt = pwndbg.aglib.memory.read_pointer_width(file + off)
            dentry = pwndbg.aglib.memory.read_pointer_width(file + off + ptrsize)
            inode = pwndbg.aglib.memory.read_pointer_width(file + off + ptrsize * 2)
    else:
        off = 0
        for i in range(7, 0x20):
            val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
            try:
                cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(val)
                if "cred" in cache.name:
                    off = i * ptrsize
                    off += ptrsize + (0x10 + ptrsize * 2) + 8  # f_cred, f_ra, f_version
                    break
            except Exception:
                pass
        _result = f"""
        struct file {{
            union {{
                struct {{
                    char _pad1[PTR_SIZE * 2];
                    struct path f_path;
                    struct inode *f_inode;
                    void *f_op;
                    char _pad2[spinlock_t_size];
#if KVERSION < KERNEL_VERSION(5, 18, 0)
                    int f_write_hint;
#endif
                    long f_count;
                    unsigned int f_flags;
                    fmode_t f_mode;
                }};
                char _pad3[{off}];
            }};
#ifdef CONFIG_SECURITY
            void *f_security;
#endif
            void *private_data;
            /* don't care about the rest */
        }};
        """
        mnt = pwndbg.aglib.memory.read_pointer_width(file + ptrsize * 2)
        dentry = pwndbg.aglib.memory.read_pointer_width(file + ptrsize * 3)
        inode = pwndbg.aglib.memory.read_pointer_width(file + ptrsize * 4)
    result += get_path_struct(mnt, dentry)
    result += get_inode_struct(inode)
    result += _result
    return result


def get_files_struct_and_offset(
    task: int, off: int, tasks: List[int], mm_offset: int
) -> Tuple[str, int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    off += TASK_COMM_LEN
    files_offset = None
    for _ in range(6):
        off += ptrsize
        fs = pwndbg.aglib.memory.read_pointer_width(task + off)
        if not pwndbg.aglib.memory.is_kernel(fs):
            continue
        val = pwndbg.aglib.memory.read_pointer_width(fs)
        if pwndbg.aglib.memory.is_kernel(val):
            continue
        files = pwndbg.aglib.memory.read_pointer_width(task + off + ptrsize)
        if not pwndbg.aglib.memory.is_kernel(files):
            continue
        val = pwndbg.aglib.memory.read_pointer_width(files)
        if pwndbg.aglib.memory.is_kernel(val):
            continue
        # found it, off is the offset of fs, so need to increment by ptrsize
        files_offset = off + ptrsize
        break
    assert files_offset, "cannot find the offset of task_struct->files"

    fdt_offset = None
    files = pwndbg.aglib.memory.read_pointer_width(task + files_offset)
    off = 0
    for _ in range(0x40):
        off += ptrsize
        fdt = pwndbg.aglib.memory.read_pointer_width(files + off)
        if not pwndbg.aglib.memory.is_kernel(fdt):
            continue
        if fdt == files + off + ptrsize:
            fdt_offset = off
            break
    assert fdt_offset, "cannot find the offset of files_struct->fdt"

    # TODO: spinlock_t_size
    structs = f"""
    #define PTR_SIZE {ptrsize}
    #define spinlock_t_size 8
    """
    # find a userland task and get a file* from it
    file = None
    for task in tasks:
        mm = pwndbg.aglib.memory.read_pointer_width(task + mm_offset)
        if pwndbg.aglib.memory.is_kernel(mm):
            files = pwndbg.aglib.memory.read_pointer_width(task + files_offset)
            fdt = pwndbg.aglib.memory.read_pointer_width(files + fdt_offset)
            max_fds = pwndbg.aglib.memory.u32(fdt)
            fd = pwndbg.aglib.memory.read_pointer_width(fdt + ptrsize)
            for i in range(max_fds):
                val = pwndbg.aglib.memory.read_pointer_width(fd + i * ptrsize)
                if pwndbg.aglib.memory.is_kernel(val):
                    file = val
                    break
            if file:
                break
    structs += get_file_struct(file)
    structs += f"""
    struct fdtable {{
        unsigned int max_fds;
        struct file **fd;
        /* don't care about the rest */
    }};
    struct files_struct {{
        union {{
            atomic_t count;
            char _pad1[{fdt_offset}];
        }};
        struct fdtable *fdt;
        /* don't care about the rest */
    }};
    """
    return structs, files_offset


def get_nsproxy_struct_and_offset(task: int, off: int) -> Tuple[str, int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    off += ptrsize
    ptr = pwndbg.aglib.memory.read_pointer_width(task + off + ptrsize * 3)
    if pwndbg.aglib.memory.is_kernel(ptr):  # check if ptrsize * 3 is blocked
        # io uring not enabled
        off += ptrsize
    struct = """
    struct nsproxy {
        refcount_t count;
        void *uts_ns;
        void *ipc_ns;
        void *mnt_ns;
        void *pid_ns_for_children;
        void *net_ns;
        void *time_ns;
        void *time_ns_for_children;
        void *cgroup_ns;
    };
    """
    return struct, off


def get_signal_struct() -> str:
    struct = """
    struct signal_struct {
        refcount_t		sigcnt;
        atomic_t		live;
        int			nr_threads;
        int			quick_threads;
        struct list_head	thread_head;
        /* don't care about the rest */
    };
    """
    return struct


def get_sp_offset(tasks: List[int], stack_offset: int, comm_offset: int) -> int:
    # &task_struct - &task_struct->thread.sp
    task = None
    ptrsize = pwndbg.aglib.arch.ptrsize
    for _task in tasks:
        stack = pwndbg.aglib.memory.read_pointer_width(_task + stack_offset)
        try:
            comm = pwndbg.aglib.memory.read(_task + comm_offset, len(ROOT_COMM)).decode()
            if stack != 0 and ROOT_COMM != comm:
                task = _task
                break
        except Exception:
            pass
    if not task:
        return 0
    for i in range(0x200):
        val = pwndbg.aglib.memory.read_pointer_width(task + i * ptrsize)
        if not pwndbg.aglib.memory.is_kernel(val):
            continue
        page = pwndbg.aglib.vmmap.find(stack)
        if val in page and val != stack:
            return i * ptrsize
    return 0


@pwndbg.aglib.kernel.typeinfo_recovery("struct task_struct", kversion=True, kbase=True)
def load_ktask_typeinfo() -> None:
    task = int(pwndbg.aglib.kernel.current_task())
    mm_offset = get_mm_offset(task)
    tasks, tasks_offset = get_tasks_offset(mm_offset)
    mm_struct = get_mm_struct(tasks, mm_offset)
    stack_offset = get_stack_offset(tasks)
    task, comm_offset = get_comm_offset(tasks)
    pid_offset = get_pid_offset(tasks, mm_offset, comm_offset)
    thread_list_offset = get_thread_list_offset(pid_offset)
    cred_struct, cred_offset = get_cred_struct_and_offset(tasks, comm_offset)
    files_structs, files_offset = get_files_struct_and_offset(task, comm_offset, tasks, mm_offset)
    nsproxy_struct, nsproxy_offset = get_nsproxy_struct_and_offset(task, files_offset)
    sp_offset = get_sp_offset(tasks, stack_offset, comm_offset)

    ptrsize = pwndbg.aglib.arch.ptrsize
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    result += mm_struct
    result += cred_struct
    result += files_structs
    result += nsproxy_struct
    result += get_signal_struct()
    if "CONFIG_STACKPROTECTOR" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_STACKPROTECTOR\n"
    result += f"#define stack_offset {stack_offset}\n"
    # TODO: use unions
    result += f"""
    struct task_struct {{
#if stack_offset
        char _pad0[{stack_offset}];
        void *stack;
        char _pad1[{tasks_offset - stack_offset - ptrsize}];
#else
        char _pad1[{tasks_offset}];
#endif
        struct list_head tasks;
        char _pad2[{mm_offset - (tasks_offset + ptrsize * 2)}];
        struct mm_struct *mm;
        struct mm_struct *active_mm;
        char __pad1[{pid_offset - (mm_offset + ptrsize * 2)}];
        pid_t pid;
        pid_t tgid;
#ifdef CONFIG_STACKPROTECTOR
        unsigned long stack_canary;
        char __pad2[{thread_list_offset - pid_offset} - sizeof(pid_t) * 2 - sizeof(unsigned long)];
#else
        char __pad2[{thread_list_offset - pid_offset} - sizeof(pid_t) * 2];
#endif
        struct list_head thread_node;
        char _pad3[{cred_offset - (thread_list_offset + ptrsize * 2)}];
        struct cred *cred;
        char _pad4[{comm_offset - (cred_offset + ptrsize)}];
        char comm[{TASK_COMM_LEN}];
        char _pad5[{files_offset - (comm_offset + TASK_COMM_LEN)}];
        struct files_struct *files;
        char _pad6[{nsproxy_offset - (files_offset + ptrsize)}];
        struct nsproxy *nsproxy;
        struct signal_struct *signal;
#if {sp_offset - nsproxy_offset - ptrsize * 2} > 0
        struct {{
            char _pad7[{sp_offset - nsproxy_offset - ptrsize * 2}];
            void *sp;
        }} thread;
#endif
    }};
    """

    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "task_structs", True)
