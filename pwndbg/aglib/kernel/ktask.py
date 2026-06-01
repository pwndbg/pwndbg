from __future__ import annotations

import os
from collections.abc import Generator

import pwndbg
import pwndbg.aglib.kernel.bpf
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg.aglib.kernel.mapletree import MapleTree
from pwndbg.lib import TypeNotRecoveredError


class NextVmaFinder:
    def __init__(self, mm: int | pwndbg.dbg_mod.Value) -> None:
        self.mm = mm

    def __iter__(self) -> Generator[int, None, None]:
        kversion = pwndbg.aglib.kernel.krelease()
        if kversion and kversion < (6, 1):
            return self.vma_struct_parse()
        mt = MapleTree(self.mm)
        return mt.maple_tree_parse()

    def vma_struct_parse(self) -> Generator[int, None, None]:
        ptrsize = pwndbg.aglib.arch.ptrsize
        start = cur = pwndbg.aglib.memory.read_pointer_width(int(self.mm))
        while cur:
            yield cur
            next = pwndbg.aglib.memory.read_pointer_width(cur + ptrsize * 2)
            if next == start:
                break
            cur = next


def get_stack_offset(tasks: list[int]) -> int:
    ptrsize = pwndbg.aglib.arch.ptrsize
    for i in range(0x10):
        for task in tasks:
            a = pwndbg.aglib.memory.read_pointer_width(task + i * ptrsize)
            b = pwndbg.aglib.memory.read_pointer_width(task + (i + 1) * ptrsize)
            # for x64, the first kernel pointer should be the stack
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


def get_tasks_offset(mm_offset: int) -> tuple[list[int], int]:
    ptrsize = pwndbg.aglib.arch.ptrsize
    tasks_offset = mm_offset - ptrsize * 2
    if "CONFIG_SMP" in pwndbg.aglib.kernel.kconfig():
        tasks_offset -= ptrsize * 8
    tasks = None
    for i in range(pwndbg.aglib.kernel.nproc()):
        task = pwndbg.aglib.kernel.current_task(i)
        if not pwndbg.aglib.memory.is_kernel(task):
            continue
        tasks = pwndbg.aglib.kernel.get_double_linked_list(task + tasks_offset, minlen=5)
        if tasks is not None:
            break
    else:
        raise TypeNotRecoveredError(
            "task_struct", f"cannot find the tasks doubly-linked list: mm_offset: {hex(mm_offset)})"
        )
    tasks = [task - tasks_offset for task in tasks]
    return tasks, tasks_offset


def get_mm_offset(task: int) -> int:
    mm_offset = None
    ptrsize = pwndbg.aglib.arch.ptrsize
    init_mm = pwndbg.aglib.symbol.lookup_symbol_addr("init_mm")
    for i in range(0x200):
        off = i * ptrsize
        val = pwndbg.aglib.memory.read_pointer_width(task + off)
        if pwndbg.aglib.kernel.in_kmem_cache(val, "mm_struct") or (init_mm and init_mm == val):
            mm_offset = off
            break
    else:
        raise TypeNotRecoveredError(
            "task_struct", f"cound not find the offset of task_struct->mm: (task: {hex(task)}"
        )
    mm_active = pwndbg.aglib.memory.read_pointer_width(task + mm_offset + ptrsize)
    if not pwndbg.aglib.kernel.in_kmem_cache(mm_active, "mm_struct"):
        # we actually found active_mm instead
        mm_offset -= ptrsize
    return mm_offset


def get_vm_area_struct(mm: int) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    if mm == 0:
        return ""
    result = ""
    off = None
    vmafinder = NextVmaFinder(mm)
    for vma in vmafinder:
        for i in range(6, 0x50):
            val = pwndbg.aglib.memory.read_pointer_width(vma + i * ptrsize)
            if pwndbg.aglib.kernel.in_kmem_cache(val, "filp"):
                off = i * ptrsize
                break
        if off is not None:
            break
    if off is None:
        return ""
    result += f"""
    struct vm_area_struct {{
        union {{
            struct {{
                unsigned long vm_start;
                unsigned long vm_end;
            }};
            struct {{
                char _pad[{off}];
                struct file *vm_file;
            }};
        }};
    }};
    """
    return result


def get_mm_struct(tasks: list[int], mm_offset: int) -> str:
    def helper(task: int, off: int, pgd: int) -> int | None:
        mm = pwndbg.aglib.memory.read_pointer_width(task + off)
        ptrsize = pwndbg.aglib.arch.ptrsize
        pgd_virt = pwndbg.aglib.kernel.phys_to_virt(pgd)
        if not pwndbg.aglib.memory.is_kernel(mm):
            return None
        for i in range(0x100):
            val = pwndbg.aglib.memory.read_pointer_width(mm + i * ptrsize)
            if val == pgd_virt:
                return i * ptrsize
            # walk the candidate virtual pgd to check if its equal to the expected phys
            val = pwndbg.aglib.kernel.pagewalk(val).phys
            if val and val == pgd:
                return i * ptrsize
        return None

    ptrsize = pwndbg.aglib.arch.ptrsize
    pgd_offset = None
    match pwndbg.aglib.arch.name:
        case "x86-64":
            reg = "cr3"
        case "aarch64":
            reg = "TTBR0_EL1"
        case _:
            raise NotImplementedError()
    regval = pwndbg.aglib.regs.read_reg(reg)
    assert regval is not None, f"cannot resolve {reg} value"
    mask = pwndbg.aglib.kernel.PAGE_ENTRY_MASK()
    pgd = regval & mask
    current_tasks = [
        pwndbg.aglib.kernel.current_task(i) for i in range(pwndbg.aglib.kernel.nproc())
    ]
    for task in tasks + current_tasks:
        if not pwndbg.aglib.memory.is_kernel(task):
            continue
        pgd_offset = helper(task, mm_offset, pgd) or helper(task, mm_offset + ptrsize, pgd)
        if pgd_offset:
            break
    else:
        raise TypeNotRecoveredError(
            "task_struct",
            f"cannot find the offset of mm_struct->pgd: (active_mm: {hex(mm_offset)})",
        )

    result = ""
    for task in tasks:
        mm_active = pwndbg.aglib.memory.read_pointer_width(task + mm_offset + ptrsize)
        if s := get_vm_area_struct(mm_active):
            result += s
            break

    result += f"""
    struct mm_struct {{
        struct {{
            char _pad1[{pgd_offset}];
            void *pgd;
        }};
        /* don't care about the rest */
    }};
    """
    return result


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


def get_pid_offset(tasks: list[int], mm_offset: int, comm_offset: int) -> int:
    maxpid = 0x400000 if pwndbg.aglib.arch.ptrsize == 8 else 0x8000
    for i in range(0x20):
        seen = set()
        off = mm_offset + i * pwndbg.aglib.arch.ptrsize
        for task in tasks[1:]:
            try:
                a = pwndbg.aglib.memory.read(task + comm_offset, len(ROOT_COMM))
                if a.decode() == ROOT_COMM:
                    continue
            except Exception:
                continue
            pid = pwndbg.aglib.memory.uint(task + off)
            tgid = pwndbg.aglib.memory.uint(task + off + pwndbg.aglib.typeinfo.uint.sizeof)
            if not (0 < pid < maxpid and 0 < tgid < maxpid) or pid in seen:
                break
            seen.add(pid)
        else:
            return off
    raise TypeNotRecoveredError(
        "task_struct",
        f"cannot find the offset of task_struct->pid (mm_offset = {hex(mm_offset)}, comm_offset = {hex(comm_offset)})",
    )


def get_thread_list_offset(pid_offset: int) -> int:
    # thread_group if <= 6.6 else thread_node
    off = pid_offset
    ptrsize = pwndbg.aglib.arch.ptrsize
    off += 21 * ptrsize
    krelease = pwndbg.aglib.kernel.krelease()
    assert krelease, "cannot find kernel version (shouldn't happen)"
    if krelease < (6, 7, 0):
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


def get_comm_offset(tasks: list[int]) -> tuple[int, int]:
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
    raise TypeNotRecoveredError("task_struct", "cannot find the offset of task_struct->comm")


def get_cred_struct_and_offset(tasks: list[int], comm_offset: int) -> tuple[str, int]:
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
    else:
        raise TypeNotRecoveredError("task_struct", "cannot find the offset of task_struct->cred")
    assert INIT_TASK, "init task not found by get_comm_offset"
    cred = pwndbg.aglib.memory.read_pointer_width(INIT_TASK + cred_offset)
    off = 0x20
    A = 0x30
    intsize = pwndbg.aglib.typeinfo.uint.sizeof
    # find cap_permitted from INIT_TASK, the distance between uid and cap_permitted is 0x30
    for i in range(A // intsize, A // intsize + 0x20):
        # sizeof(kernel_cap_t) == 8 even for 32 bits
        val = pwndbg.aglib.memory.u64(cred + i * intsize)
        if val == 0x000001FFFFFFFFFF:  # is this true for all 5.x and 6.x?
            off = i * intsize - A
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


def get_path_struct(dentry: int | None) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    result = ""
    off = 0
    if dentry:
        for i in range(3, 0x20):
            try:
                ptr = pwndbg.aglib.memory.read_pointer_width(dentry + i * ptrsize)
                if not pwndbg.aglib.memory.is_kernel(ptr):
                    continue
                name = pwndbg.aglib.memory.string(ptr).decode()
                if len(name) > 2:
                    off = (i - 1) * ptrsize - 8
                    break
            except Exception:
                pass
    result += f"""
    struct dentry {{
#if {off}
        char _pad[{off}];
        struct dentry *d_parent;
        u64 hash_len;
        struct {{
            const unsigned char *name;
        }} d_name;
#else
        char a;
#endif
    }};
    """
    result += """
    struct vfsmount {
        struct dentry *mnt_root;	/* root of the mounted tree */
        struct super_block *mnt_sb;	/* pointer to superblock */
        int mnt_flags;
    };
    struct mount {
        struct hlist_node mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt; // path->mnt points here
        /* ... */
    };
    struct path {
        struct vfsmount *mnt;
        struct dentry *dentry;
    };
    """
    return result


def get_inode_struct(inode: int | None) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    off = 0x40
    if inode:
        for i in range(5, 0x10):
            val = pwndbg.aglib.memory.u(inode + i * ptrsize)
            if val == pwndbg.aglib.arch.unsigned(-1) or pwndbg.aglib.memory.is_kernel(val):
                continue
            off = i * ptrsize
            break
    return f"""
    struct inode {{
#if 0
	umode_t			i_mode;
	unsigned short		i_opflags;
	unsigned int		i_flags;
#ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl	*i_acl;
	struct posix_acl	*i_default_acl;
#endif
	kuid_t			i_uid;
	kgid_t			i_gid;

	const struct inode_operations	*i_op;
	struct super_block	*i_sb;
	struct address_space	*i_mapping;

#ifdef CONFIG_SECURITY
	void			*i_security;
#endif
#endif
        char _pad[{off}];
        unsigned long i_ino;
    }};
    """


def get_file_struct(file: int | None) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    result = ""
    krelease = pwndbg.aglib.kernel.krelease()
    assert krelease, "cannot find kernel version (shouldn't happen)"
    kbase: int | None = pwndbg.aglib.kernel.kbase()
    if "CONFIG_SECURITY" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_SECURITY\n"
    result += """
    typedef unsigned int fmode_t;
    """
    dentry = inode = None
    off: int
    _result = ""
    intsize = pwndbg.aglib.typeinfo.uint.sizeof
    if not file or krelease >= (6, 12):
        # find f_op
        off = 0
        if file:
            for i in range(1, 0x20):
                val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
                if kbase and val > kbase:
                    off = i * ptrsize - pwndbg.aglib.typeinfo.uint.sizeof
                    if not pwndbg.aglib.memory.uint(file + off):
                        off -= pwndbg.aglib.typeinfo.uint.sizeof
                    break
        # this should work for the most recent versions
        _result = f"""
        struct file {{
            char _pad2[{off}];
            fmode_t f_mode;
            void* f_op;
            void *f_mapping;
            void *private_data;
            struct inode *f_inode;
            unsigned int f_flags;
            unsigned int f_iocb_flags;
            const struct cred *f_cred;
#if KVERSION >= KERNEL_VERSION(6, 15, 0)
            void *f_owner;
#endif
            /* --- cacheline 1 boundary (64 bytes) --- */
            struct path f_path;
            /* don't care about the rest */
        }};
        """
        if off > 0 and file is not None:
            off += intsize
            off = (off // ptrsize) * ptrsize + (ptrsize if off % ptrsize else 0)
            dentry = pwndbg.aglib.memory.read_pointer_width(
                file + off + intsize * 2 + ptrsize * (6 if krelease < (6, 15) else 7)
            )
            inode = pwndbg.aglib.memory.read_pointer_width(file + off + ptrsize * 3)
    elif krelease >= (6, 5):
        # find the cache that contains the inode
        inode_offset = 0
        fmode_offset = ptrsize * 2 + 8
        for i in range(2, 0x20):
            val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
            if pwndbg.aglib.kernel.in_kmem_cache(val, "inode", strict=False):
                inode_offset = (i - 2) * ptrsize
                break
        if inode_offset == 0:  # fallback by finding f_op
            for i in range(2, 0x20):
                val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
                if kbase and val > kbase and pwndbg.aglib.memory.is_kernel(val):
                    inode_offset = (i - 3) * ptrsize
                    break
        for i in range(2 * ptrsize, inode_offset, intsize):
            # usually the fmode of stdin/out/err, uint or u32?
            if pwndbg.aglib.memory.uint(file + i) == 0xE0003:
                fmode_offset = i
                break
            # but if we didn't find it, that's fine as well
        _result = f"""
        struct file {{
            union {{
                struct {{
                    char _pad1[{fmode_offset}];
                    fmode_t f_mode;
                }};
                char _pad2[{inode_offset}];
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
        if inode_offset > 0:
            dentry = pwndbg.aglib.memory.read_pointer_width(file + inode_offset + ptrsize)
            inode = pwndbg.aglib.memory.read_pointer_width(file + inode_offset + ptrsize * 2)
    else:
        off = 0
        for i in range(7, 0x20):
            val = pwndbg.aglib.memory.read_pointer_width(file + i * ptrsize)
            if pwndbg.aglib.kernel.in_kmem_cache(val, "cred_jar"):
                off = i * ptrsize
                off += ptrsize + (0x10 + ptrsize * 2) + 8  # f_cred, f_ra, f_version
                break
        fmode_offset = 6 * ptrsize + 8 + ptrsize + 4
        for i in range(6 * ptrsize, off, 4):
            if pwndbg.aglib.memory.u32(file + i) == 0xE0003:  # usually the fmode of stdin/out/err
                fmode_offset = i
                break
        _result = f"""
        struct file {{
            union {{
                struct {{
                    char _pad1[{ptrsize * 2}];
                    struct path f_path;
                    struct inode *f_inode;
                    void *f_op;
                }};
                struct {{
                    char _pad2[{fmode_offset}];
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
        dentry = pwndbg.aglib.memory.read_pointer_width(file + ptrsize * 3)
        inode = pwndbg.aglib.memory.read_pointer_width(file + ptrsize * 4)
    result += get_path_struct(dentry)
    result += get_inode_struct(inode)
    result += _result
    return result


def get_files_struct_and_offset(
    task: int, off: int, tasks: list[int], mm_offset: int
) -> tuple[str, int]:
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
    else:
        raise TypeNotRecoveredError("task_struct", "cannot find the offset of task_struct->files")

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
    else:
        raise TypeNotRecoveredError("files_struct", "cannot find the offset of files_struct->fdt")

    # find a userland task and get a file* from it
    file = None
    for task in tasks:
        mm = pwndbg.aglib.memory.read_pointer_width(task + mm_offset)
        if pwndbg.aglib.memory.is_kernel(mm):
            files = pwndbg.aglib.memory.read_pointer_width(task + files_offset)
            fdt = pwndbg.aglib.memory.read_pointer_width(files + fdt_offset)
            max_fds = pwndbg.aglib.memory.uint(fdt)
            fd = pwndbg.aglib.memory.read_pointer_width(fdt + ptrsize)
            for i in range(max_fds):
                val = pwndbg.aglib.memory.read_pointer_width(fd + i * ptrsize)
                if pwndbg.aglib.memory.is_kernel(val):
                    file = val
                    break
            if file:
                break
    structs = get_file_struct(file)
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


def get_nsproxy_struct_and_offset(task: int, off: int) -> tuple[str, int]:
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


def get_sighand_struct(task: int, nsproxy_offset: int) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    sighand = pwndbg.aglib.memory.read_pointer_width(task + nsproxy_offset + ptrsize * 2)
    off = ptrsize
    kversion = pwndbg.aglib.kernel.krelease()
    if not kversion or kversion >= (5, 3):
        for i in range(0x20):
            if pwndbg.aglib.kernel.get_double_linked_list(sighand + i * ptrsize):
                off = (i + 2) * ptrsize
                break
        else:
            return """
            struct sighand_struct { char _a; };
            """
    result = f"""
#define _NSIG		64
#define _NSIG_BPW	{pwndbg.aglib.arch.ptrbits}
#define _NSIG_WORDS	(_NSIG / _NSIG_BPW)
    """
    if pwndbg.aglib.arch.name in ("x86-64", "aarch64"):
        result += "#define __ARCH_HAS_SA_RESTORER\n"
    result += """
    #define _NSIG 64
    typedef void __signalfn_t(int);
    typedef __signalfn_t *__sighandler_t;
    typedef void __restorefn_t(void);
    typedef __restorefn_t *__sigrestore_t;
    typedef struct {
        unsigned long sig[_NSIG_WORDS];
    } sigset_t;
    struct sigaction {
#ifndef __ARCH_HAS_IRIX_SIGACTION
        __sighandler_t	sa_handler;
        unsigned long	sa_flags;
#else
        unsigned int	sa_flags;
        __sighandler_t	sa_handler;
#endif
#ifdef __ARCH_HAS_SA_RESTORER
        __sigrestore_t sa_restorer;
#endif
        sigset_t	sa_mask;	/* mask last for extensibility */
    };

    struct k_sigaction {
        struct sigaction sa;
#ifdef __ARCH_HAS_KA_RESTORER
        __sigrestore_t ka_restorer;
#endif
    };
    """
    result += f"""
    struct sighand_struct {{
        char _pad[{off}];
        struct k_sigaction	action[_NSIG];
    }};
    """
    return result


def get_sp_offset(tasks: list[int], stack_offset: int, comm_offset: int) -> int:
    # &task_struct - &task_struct->thread.sp
    # only one other ptr in the task_struct that belongs to the same page chunk
    task = stack = None
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
    if not task or stack is None:
        return 0
    for i in range(0x200):
        val = pwndbg.aglib.memory.read_pointer_width(task + i * ptrsize)
        if not pwndbg.aglib.memory.is_kernel(val):
            continue
        page = pwndbg.aglib.vmmap.find(stack)
        if page and val in page and val != stack:
            return i * ptrsize
    return 0


@pwndbg.aglib.kernel.typeinfo_recovery(
    "struct task_struct", requires_kversion=True, requires_kbase=True
)
def recover_ktask_typeinfo() -> str:
    task = pwndbg.aglib.kernel.current_task()
    assert task, "current task not found"
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
    sighand_struct = get_sighand_struct(task, nsproxy_offset)
    sp_offset = get_sp_offset(tasks, stack_offset, comm_offset)

    ptrsize = pwndbg.aglib.arch.ptrsize
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    result += mm_struct
    result += cred_struct
    result += files_structs
    result += nsproxy_struct
    result += sighand_struct
    result += get_signal_struct()
    if "CONFIG_STACKPROTECTOR" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_STACKPROTECTOR\n"
    result += f"#define stack_offset {stack_offset}\n"
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
        char _pad4[{comm_offset - cred_offset - ptrsize}];
        char comm[{TASK_COMM_LEN}];
        char _pad5[{files_offset - (comm_offset + TASK_COMM_LEN)}];
        struct files_struct *files;
        char _pad6[{nsproxy_offset - (files_offset + ptrsize)}];
        struct nsproxy *nsproxy;
        struct signal_struct *signal;
        struct sighand_struct *sighand;
#if {sp_offset - nsproxy_offset - ptrsize * 3} > 0
        struct {{
            char _pad7[{sp_offset - nsproxy_offset - ptrsize * 3}];
#ifdef __x86_64__
            void *sp;
#endif
#ifdef __aarch64__
            struct {{ void *sp; }} cpu_context;
#endif
        }} thread;
#endif
    }};
    """
    return result


@pwndbg.lib.cache.cache_until("stop")
def get_filepath(file: int | pwndbg.dbg_mod.Value) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    file = pwndbg.aglib.memory.get_typed_pointer("struct file", file)
    if int(file) == 0:
        return ""
    dentry = file["f_path"]["dentry"]
    if not dentry.dereference().type.has_field("d_name"):
        return "?"
    mount = pwndbg.aglib.memory.get_typed_pointer(
        "struct mount", int(file["f_path"]["mnt"]) - 4 * ptrsize
    )
    path = []
    while dentry:
        try:
            nxt = dentry["d_parent"]
            if int(dentry) == int(nxt) or int(dentry) == int(mount["mnt"]["mnt_root"]):
                mnt_parent = mount["mnt_parent"]
                if int(mount) != int(mnt_parent):
                    dentry = mount["mnt_mountpoint"]
                    mount = mnt_parent
                    continue
                nxt = None
            name = pwndbg.aglib.memory.string(int(dentry["d_name"]["name"])).decode()
            path.append(name)
            dentry = nxt
        except Exception:
            break
    if not path:
        return ""
    path = os.path.join(*path[::-1])
    ino = int(file["f_inode"]["i_ino"])
    if path in ["UNIX", "NETLINK", "TCP", "TCPv6", "UDP", "UDPv6", "PACKET"]:
        path = f"[{path}] socket:[{ino}]"
    elif path and not path.startswith("/"):
        path = f"anon:[{path}]"
    elif path == "":
        path = f"pipe:[{ino}]"
    return path


def resolve_addr_if_file(mm: int | pwndbg.dbg_mod.Value, addr: int) -> str:
    # TODO: optimize this
    if pwndbg.aglib.typeinfo.lookup_types("struct vm_area_struct") is None:
        return ""
    vmafinder = NextVmaFinder(mm)
    for _vma in vmafinder:
        vma = pwndbg.aglib.memory.get_typed_pointer("struct vm_area_struct", _vma)
        if int(vma["vm_start"]) <= addr < int(vma["vm_end"]):
            return get_filepath(vma["vm_file"])
    return ""


@pwndbg.aglib.kernel.typeinfo_recovery("struct seccomp", requires_kversion=True)
def recover_seccomp_typeinfo(_filter: int) -> str:
    ptrsize = pwndbg.aglib.arch.ptrsize
    result = pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += pwndbg.aglib.kernel.bpf.get_struct_bpf_prog()
    result += f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    off = None
    for i in range(1, 10):
        ptr = pwndbg.aglib.memory.read_pointer_width(_filter + i * ptrsize)
        page = pwndbg.aglib.vmmap.find(ptr)
        if page and "vmalloc" in page.objfile:
            off = (i - 1) * ptrsize
            break
    else:
        raise TypeNotRecoveredError(
            "seccomp_filter", f"cannot find seccomp_filter->prog (filter @ {hex(_filter)})"
        )
    result += f"""
    struct seccomp_filter {{
        char _pad[{off}];
        struct seccomp_filter *prev;
        struct bpf_prog *prog;
    }};
    """
    result += """
    struct seccomp {
        int mode;
#if KVERSION >= KERNEL_VERSION(5, 9, 0)
        atomic_t filter_count;
#endif
        struct seccomp_filter *filter;
    };
    """
    return result


def seccomp(task: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value | None:
    # recover seccomp on a task by task basis cuz it doesn't always exist
    krelease = pwndbg.aglib.kernel.krelease()
    ptrsize = pwndbg.aglib.arch.ptrsize
    val = task.dereference().type._offsetof("sighand")
    assert val
    start = int(task) + val
    val = pwndbg.aglib.typeinfo.lookup_types("sigset_t").sizeof
    assert val > 0
    start += val * 3 + ptrsize * 2 + val + ptrsize * 4
    seccomp = _filter = None
    for i in range(5):
        if pwndbg.aglib.memory.uint(start + i * ptrsize) > 0x1000:  # mode
            continue
        additional = 1 if pwndbg.aglib.arch.ptrsize == 8 or (krelease and krelease < (5, 9)) else 2
        val = pwndbg.aglib.memory.read_pointer_width(start + (i + additional) * ptrsize)
        if pwndbg.aglib.kernel.in_kmem_cache(val, "kmalloc-", strict=False):
            seccomp = start + i * ptrsize
            _filter = val
            break
    if seccomp is None or _filter is None:
        return None
    recover_seccomp_typeinfo(_filter)
    return pwndbg.aglib.memory.get_typed_pointer("struct seccomp", seccomp)
