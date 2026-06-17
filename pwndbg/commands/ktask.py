"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse
import ctypes
from collections.abc import Generator

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib
import pwndbg.lib.cache
from pwndbg import color
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.color import message
from pwndbg.lib.exception import IndentContextManager


class pt_regs_x86_64(ctypes.Structure):
    _fields_ = (
        ("r15", ctypes.c_ulong),
        ("r14", ctypes.c_ulong),
        ("r13", ctypes.c_ulong),
        ("r12", ctypes.c_ulong),
        ("rbp", ctypes.c_ulong),
        ("rbx", ctypes.c_ulong),
        ("r11", ctypes.c_ulong),
        ("r10", ctypes.c_ulong),
        ("r9", ctypes.c_ulong),
        ("r8", ctypes.c_ulong),
        ("rax", ctypes.c_ulong),
        ("rcx", ctypes.c_ulong),
        ("rdx", ctypes.c_ulong),
        ("rsi", ctypes.c_ulong),
        ("rdi", ctypes.c_ulong),
        ("orig_ax", ctypes.c_ulong),
        ("rip", ctypes.c_ulong),
        ("cs", ctypes.c_uint64),
        ("flags", ctypes.c_ulong),
        ("rsp", ctypes.c_ulong),
        ("ss", ctypes.c_uint64),
    )


class pt_regs_aarch64(ctypes.Structure):
    _fields_ = (
        ("x0", ctypes.c_uint64),
        ("x1", ctypes.c_uint64),
        ("x2", ctypes.c_uint64),
        ("x3", ctypes.c_uint64),
        ("x4", ctypes.c_uint64),
        ("x5", ctypes.c_uint64),
        ("x6", ctypes.c_uint64),
        ("x7", ctypes.c_uint64),
        ("x8", ctypes.c_uint64),
        ("x9", ctypes.c_uint64),
        ("x10", ctypes.c_uint64),
        ("x11", ctypes.c_uint64),
        ("x12", ctypes.c_uint64),
        ("x13", ctypes.c_uint64),
        ("x14", ctypes.c_uint64),
        ("x15", ctypes.c_uint64),
        ("x16", ctypes.c_uint64),
        ("x17", ctypes.c_uint64),
        ("x18", ctypes.c_uint64),
        ("x19", ctypes.c_uint64),
        ("x20", ctypes.c_uint64),
        ("x21", ctypes.c_uint64),
        ("x22", ctypes.c_uint64),
        ("x23", ctypes.c_uint64),
        ("x24", ctypes.c_uint64),
        ("x25", ctypes.c_uint64),
        ("x26", ctypes.c_uint64),
        ("x27", ctypes.c_uint64),
        ("x28", ctypes.c_uint64),
        ("x29", ctypes.c_uint64),
        ("x30", ctypes.c_uint64),
        ("sp", ctypes.c_uint64),
        ("pc", ctypes.c_uint64),
        ("pstate", ctypes.c_uint64),
        ("orig_x0", ctypes.c_uint64),
        ("syscallno", ctypes.c_int32),  # ends at offset 0x11c but the struct is 0x120 bytes
    )


class Kthread:
    def __init__(self, thread: pwndbg.dbg_mod.Value | int) -> None:
        self.thread = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", thread)

    @pwndbg.lib.cache.cache_until("stop")
    def files(self) -> tuple[tuple[int, pwndbg.dbg_mod.Value], ...]:
        fdt = self.thread["files"]["fdt"]
        fds = fdt["fd"]
        files = []
        for i in range(int(fdt["max_fds"])):
            file = fds[i]
            addr = int(file)
            if addr == 0:
                continue
            files.append((i, file))
        return tuple(files)

    @property
    def mm(self) -> pwndbg.dbg_mod.Value | None:
        mm = self.thread["mm"]
        if int(mm) != 0:
            return mm
        # for anonymous tasks
        mm = self.thread["active_mm"]
        if int(mm) != 0:
            return mm
        return None

    @property
    def pgd(self) -> int | None:
        if not self.mm:
            return None
        return int(self.mm["pgd"])

    @property
    def stack(self) -> int | None:
        if self.thread.dereference().type.has_field("thread"):
            a = self.thread["thread"]
            match pwndbg.aglib.arch.name:
                case "x86-64":
                    pass
                case "aarch64":
                    a = self.thread["thread"]["cpu_context"]
            return int(a["sp"])
        if self.thread.dereference().type.has_field("stack"):
            return int(self.thread["stack"])
        # the offset of stack was not recovered
        return None

    @property
    def canary(self) -> int | None:
        if self.thread.dereference().type.has_field("stack_canary"):
            return int(self.thread["stack_canary"])
        # the offset of stack was not recovered
        return None

    @property
    def name(self) -> str:
        return self.thread["comm"].string()

    @property
    def pid(self) -> int:
        return int(self.thread["pid"])

    @property
    def user_task(self) -> bool:
        return int(self.thread["mm"]) != 0

    @property
    def uid(self) -> int:
        return int(self.thread["cred"]["uid"]["val"])

    @property
    def gid(self) -> int:
        return int(self.thread["cred"]["gid"]["val"])

    @property
    def nsproxy(self) -> list[tuple[str, int]]:
        proxy = self.thread["nsproxy"]
        result = []
        for ns in proxy.dereference().type.fields()[1:]:
            name = ns.name
            val = int(proxy[name])
            result.append((f"{name:<20}", val))
        return result

    @property
    def sighand(self) -> Generator[tuple[int, int], None, None]:
        if not self.thread["sighand"].dereference().type.has_field("action"):
            return
        sighand = self.thread["sighand"]["action"]
        for i in range(sighand.type.array_len):
            action = sighand[i]["sa"]
            yield (int(action["sa_handler"]), int(action["sa_flags"]))

    def pt_regs(self) -> tuple[list[tuple[str, int]] | None, str | None]:
        page = pwndbg.aglib.vmmap.find(self.stack)
        if not self.stack or not self.user_task or not page:
            # pt_regs may not be saved at the end of the stack if otherwise
            return None, None
        pt_regs = syscall_reg = None
        match pwndbg.aglib.arch.name:
            case "x86-64":
                pt_regs = pt_regs_x86_64
                sz = ctypes.sizeof(pt_regs)
                # the name is differnet than the canonical name
                syscall_reg = "orig_ax"
            case "aarch64":
                pt_regs = pt_regs_aarch64
                sz = ctypes.sizeof(pt_regs) + 0x20
                kversion = pwndbg.aglib.kernel.krelease()
                if kversion and (5, 10) <= kversion < (6, 18):
                    sz += 0x10
                syscall_reg = "syscallno"
            case _:
                raise NotImplementedError()
        start = page.end - sz
        regs = pt_regs.from_buffer_copy(pwndbg.aglib.memory.read(start, sz))
        regs = [(name, int(getattr(regs, name))) for name, *_ in regs._fields_]
        return regs, syscall_reg

    @property
    def user_stack(self) -> int | None:
        pt_regs, _ = self.pt_regs()
        if not pt_regs:
            return None
        stack_reg = pwndbg.aglib.regs.stack
        for reg, val in pt_regs:
            if stack_reg and stack_reg == reg:
                return val
        return None

    def seccomp(self) -> list[pwndbg.dbg_mod.Value] | None:
        task = self.thread
        seccomp = None
        if task.dereference().type.has_field("seccomp"):
            seccomp = task["seccomp"].address
        if seccomp is None:
            seccomp = pwndbg.aglib.kernel.ktask.seccomp(task)
            if seccomp is None:
                return None
        result = []
        cur = seccomp["filter"]
        while int(cur):
            result.append(cur["prog"])
            cur = cur["prev"]
        return result

    def __str__(self) -> str:
        prefix = str(pwndbg.config.backtrace_prefix)
        kcurrent = pwndbg.commands.kcurrent.select_kthread_from_pid(None)
        if kcurrent and int(kcurrent.thread) != int(self.thread):
            prefix = " " * len(prefix)
        prefix = color.blue(prefix)
        thread = color.blue(hex(int(self.thread)))
        pid = f"[pid {self.pid}]"
        pid = color.blue(f"{pid:<11}")
        cpu = "[cpu: -]"  # not scheduled on a cpu
        for i in range(pwndbg.aglib.kernel.nproc()):
            if pwndbg.aglib.kernel.current_task(i) == int(self.thread):
                cpu = f"[cpu: {i}]"
                break
        cpulen = 7 + len(str(pwndbg.aglib.kernel.nproc() - 1))
        cpu = color.red(f"{cpu:<{cpulen}}")
        namelen = pwndbg.aglib.kernel.ktask.TASK_COMM_LEN
        prefix = f"{prefix} {pid} {cpu} task @ {thread}: {self.name:<{namelen}}"
        user = "[user task]" if self.user_task else ""
        uid = f"[uid: {self.uid}]"
        gid = f"[gid: {self.gid}]"
        desc = color.red(f"{uid:<11} {gid:<11} {user}")
        return f"{prefix} {desc}"


class Ktask:
    def __init__(self, task: pwndbg.dbg_mod.Value | int) -> None:
        task = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", task)
        self.task = task
        threads = []
        signal = task["signal"]
        # Iterate through all threads in the task_struct's thread list.
        for thread in for_each_entry(signal["thread_head"], "struct task_struct", "thread_node"):
            if not pwndbg.aglib.memory.is_kernel(int(thread)):
                continue
            kthread = Kthread(thread)
            threads.append(kthread)
        self.threads = threads


@pwndbg.lib.cache.cache_until("stop")
def get_ktasks() -> tuple[Ktask, ...]:
    pwndbg.aglib.kernel.ktask.recover_ktask_typeinfo()
    try:
        seen = set()
        for i in range(pwndbg.aglib.kernel.nproc()):
            task = pwndbg.aglib.kernel.current_task(i)
            if not pwndbg.aglib.memory.is_kernel(task):
                continue
            seen.add(task)
        init_task = pwndbg.aglib.kernel.init_task()
        task = init_task
        if task not in seen and pwndbg.aglib.memory.is_kernel(task):
            seen.add(task)
        if init_task is not None:
            _init_task = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", init_task)
            for task in for_each_entry(_init_task["tasks"], "struct task_struct", "tasks"):
                if (task := int(task)) and task not in seen and pwndbg.aglib.memory.is_kernel(task):
                    seen.add(task)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR (get_ktasks): {e}"))
        return ()
    return tuple(Ktask(task) for task in seen)


parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")
parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")
parser.add_argument("--pid", nargs="?", type=int, help="A pid to search for")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def ktask(task_name: str | None = None, pid: int | None = None) -> None:
    pwndbg.aglib.kernel.ktask.recover_ktask_typeinfo()
    threads = []
    for task in get_ktasks():
        for thread in task.threads:
            if task_name is not None and task_name not in thread.name:
                continue
            if pid is not None and pid != thread.pid:
                continue
            threads.append(thread)
    threads.sort(key=lambda thread: (thread.pid, thread.name))
    indent = IndentContextManager()
    for thread in threads:
        indent.print(thread)
