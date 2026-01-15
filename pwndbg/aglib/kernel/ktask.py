from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo

"""
    struct list_head tasks;
#ifdef CONFIG_SMP
    struct plist_node pushable_tasks; // 5 ptr size
    struct rb_node pushable_dl_tasks; // 3 ptr size
#endif

    struct mm_struct *mm; // Nullable
    struct mm_struct *active_mm;
"""


def get_tasks_offset(task: int) -> Tuple[List[int], int]:
    for i in range(0x200):
        off = i * pwndbg.aglib.arch.ptrsize
        val = task + off
        if not pwndbg.aglib.memory.is_kernel(val):
            continue
        head = pwndbg.aglib.memory.read_pointer_width(val)
        tasks = pwndbg.aglib.kernel.symbol.get_double_linked_list(head)
        if tasks and len(tasks) >= 10:
            tasks = [task - off for task in tasks]
            return tasks, off
    raise AssertionError("could not find the offset of task_struct->tasks")


def get_mm_struct_and_offset(task: int, tasks_offset: int) -> Tuple[str, int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    off = tasks_offset + 2 * ptrsize
    val = pwndbg.aglib.memory.read_pointer_width(task + off)
    adjust = None
    if val == 0:
        _val = pwndbg.aglib.memory.read_pointer_width(task + off + ptrsize)
        if pwndbg.aglib.memory.is_kernel(_val):
            adjust = 0
    if adjust is None and not pwndbg.aglib.memory.is_kernel(val):
        adjust = 8 * ptrsize
    if adjust:
        off += adjust

    active_mm = pwndbg.aglib.memory.read_pointer_width(task + off + ptrsize)
    pgd_offset = None
    match pwndbg.aglib.arch.name:
        case "x86-64":
            reg = "cr3"
        case "aarch64":
            # TODO: userland pc?
            reg = "TTBR1_EL1"
        case _:
            raise NotImplementedError()
    mask = pwndbg.aglib.kernel.arch_paginginfo().PAGE_ENTRY_MASK
    pgd_virt = pwndbg.aglib.kernel.phys_to_virt(pwndbg.aglib.regs.read_reg(reg) & mask)
    for i in range(0x100):
        if pwndbg.aglib.memory.read_pointer_width(active_mm + i * ptrsize) == pgd_virt:
            pgd_offset = i * ptrsize
            break
    assert pgd_offset, "cannot find the offset of mm_struct->pgd"
    struct = f"""
    struct mm_struct {{
        char _pad1[{pgd_offset}];
        void *pgd;
        /* don't care about the rest */
    }}
    """

    return struct, off


"""
    pid_t				pid;
    pid_t				tgid;
"""

ROOT_COMM = "swapper/0"


def get_pid_offset(tasks: List[int], mm_offset: int, comm_offset: int) -> int:
    maxpid = 0x400000 if pwndbg.aglib.arch.ptrsize == 8 else 0x8000
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
        else:
            return off
    raise AssertionError("cannot find the offset of task_struct->pid")


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


def get_comm_offset(tasks: List[int]) -> Tuple[int, int]:
    for task in tasks:
        off = 0
        for _ in range(0x300):
            try:
                s = pwndbg.aglib.memory.read(task + off, len(ROOT_COMM))
                if s.decode() == ROOT_COMM:
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
    assert cred_offset, "cannot find the offset of task_struct->cred"
    """
    """
    kversion = pwndbg.aglib.kernel.krelease()
    assert kversion, "kernel version needed to recover struct cred"
    if kversion < (6, 1, 69):
        off = 4
    elif kversion < (6, 2):
        off = ptrsize
    elif kversion < (6, 6, 8):
        off = 4
        for i in range(6):
            if pwndbg.aglib.memory.is_kernel(i * ptrsize + cred_offset):
                off += 4 + ptrsize + 4
    else:
        off = ptrsize
    struct = f"""
    struct cred {{
#if 0
        atomic_t usage; // ~v6.1.69, v6.2~v6.6.7
        atomic_long_t usage; // v6.1.69~v6.1.143, v6.6.8~
    #ifdef CONFIG_DEBUG_CREDENTIALS // ~v6.6.7
        atomic_t subscribers; // ~v6.6.7
        void *put_addr; // ~v6.6.7
        unsigned magic; // ~v6.6.7
    #endif // ~v6.6.7
#endif
        char _pad1[{off}];
        kuid_t uid;
        kgid_t gid;
        kuid_t suid;
        kgid_t sgid;
        kuid_t euid;
        kgid_t egid;
        kuid_t fsuid;
        kgid_t fsgid;
        /* don't care about the rest */
    }};
    """
    return struct, cred_offset


TASK_COMM_LEN = 0x10


def get_files_struct_and_offset(task: int, off: int) -> Tuple[str, int]:
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

    offset_fdt = None
    files = pwndbg.aglib.memory.read_pointer_width(task + files_offset)
    off = 0
    print(hex(files))
    for _ in range(0x40):
        off += ptrsize
        fdt = pwndbg.aglib.memory.read_pointer_width(files + off)
        if not pwndbg.aglib.memory.is_kernel(fdt):
            continue
        if fdt == files + off + ptrsize:
            offset_fdt = off
            break
    assert offset_fdt, "cannot find the offset of files_struct->fdt"

    structs = f"""
    #define PTR_SIZE {ptrsize}
    #define spinlock_t_size {offset_fdt} - sizeof(atomic_t) - PTR_SIZE * 2
    """
    structs += """
    struct file {
        char _pad2[spinlock_t_size];
        unsigned int f_mode;
        void* f_op;
        /* don't care about the rest */
    }
    struct fdtable {
        unsigned int max_fds;
        struct file **fd;
        /* don't care about the rest */
    }
    struct files_struct {
        atomic_t count;
        char _pad1[spinlock_t_size + PTR_SIZE * 2]; // spinlock + list_head
        struct fdtable *fdt;
        /* don't care about the rest */
    }
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
    }
    """
    return struct


def load_ktask_typeinfo() -> None:
    if pwndbg.aglib.typeinfo.lookup_types("struct task_struct") is not None:
        return
    if pwndbg.aglib.kernel.krelease() is None:
        return
    task = pwndbg.aglib.kernel.arch_symbols().current_task()
    assert task, "cannot find kernel task to start recovering typeinfo"
    task = int(task)
    tasks, tasks_offset = get_tasks_offset(task)
    mm_struct, mm_offset = get_mm_struct_and_offset(task, tasks_offset)
    task, comm_offset = get_comm_offset(tasks)
    pid_offset = get_pid_offset(tasks, mm_offset, comm_offset)
    cred_struct, cred_offset = get_cred_struct_and_offset(tasks, comm_offset)
    files_structs, files_offset = get_files_struct_and_offset(task, comm_offset)
    nsproxy_struct, nsproxy_offset = get_nsproxy_struct_and_offset(task, files_offset)

    ptrsize = pwndbg.aglib.arch.ptrsize
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += mm_struct
    result += cred_struct
    result += files_structs
    result += nsproxy_struct
    result += get_signal_struct()
    result += f"""
    struct task_struct {{
        char _pad1[{tasks_offset}];
        struct list_head tasks;
        char _pad2[{mm_offset - (tasks_offset + ptrsize * 2)}]
        struct mm_struct *mm;
        struct mm_struct *active_mm;
        char __pad1[{pid_offset - (mm_offset + ptrsize * 2)}];
        pid_t pid;
        char _pad3[{cred_offset - pid_offset} - sizeof(pid_t)];
        struct cred *cred;
        char _pad4[{comm_offset - (cred_offset + ptrsize)}];
        char comm[{TASK_COMM_LEN}];
        char _pad5[{files_offset - (comm_offset + TASK_COMM_LEN)}];
        struct files_struct *files;
        char _pad6[{nsproxy_offset - (files_offset + ptrsize)}];
        struct nsproxy *nsproxy;
        struct signal_struct *signal;
        /* don't care about the rest */
    }}
    """

    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "task_structs", True)
