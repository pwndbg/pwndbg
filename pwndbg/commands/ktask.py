"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse
import ctypes

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.symbol
import pwndbg.color as color
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib
import pwndbg.lib.cache
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.lib.exception import IndentContextManager


class pt_regs_x86_64(ctypes.Structure):
    _fields_ = [
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
    ]


class pt_regs_aarch64(ctypes.Structure):
    _fields_ = [
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
    ]


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
    def mm(self) -> pwndbg.dbg_mod.Value:
        mm = self.thread["mm"]
        if int(mm) != 0:
            return mm
        # for anonymous tasks
        mm = self.thread["active_mm"]
        if int(mm) != 0:
            return mm
        return None

    @property
    def pgd(self) -> int:
        return int(self.mm["pgd"])

    @property
    def stack(self) -> int | None:
        if self.thread.dereference().type.has_field("thread"):
            return int(self.thread["thread"]["sp"])
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

    def pt_regs(self) -> tuple[list[tuple[str, int]] | None, str | None]:
        if not self.stack or not self.user_task:
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
        page = pwndbg.aglib.vmmap.find(self.stack)
        start = page.end - sz
        regs = pt_regs.from_buffer_copy(pwndbg.aglib.memory.read(start, sz))
        regs = [(name, int(getattr(regs, name))) for name, *_ in regs._fields_]
        return regs, syscall_reg

    def __str__(self) -> str:
        prefix = str(pwndbg.config.backtrace_prefix)
        if int(pwndbg.aglib.kernel.current_task()) != int(self.thread):
            prefix = " " * len(prefix)
        prefix = color.blue(prefix)
        thread = color.blue(hex(int(self.thread)))
        pid = f"[pid {self.pid}]"
        pid = color.blue(f"{pid:<11}")
        cpu = "[cpu: -]"  # not scheduled on a cpu
        for i in range(pwndbg.aglib.kernel.nproc()):
            if int(pwndbg.aglib.kernel.current_task(i)) == int(self.thread):
                cpu = f"[cpu: {i}]"
        cpulen = 7 + len(str(pwndbg.aglib.kernel.nproc() - 1))
        cpu = color.red(f"{cpu:<{cpulen}}")
        desc = " "
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
            kthread = Kthread(thread)
            threads.append(kthread)
        self.threads = threads


@pwndbg.lib.cache.cache_until("stop")
def get_ktasks() -> tuple[Ktask, ...]:
    if not pwndbg.aglib.kernel.ktask.load_ktask_typeinfo():
        return ()
    tasks: list[Ktask] = []
    try:
        seen = set()
        for i in range(0, pwndbg.aglib.kernel.nproc()):
            task = int(pwndbg.aglib.kernel.current_task(i))
            seen.add(task)
            tasks.append(Ktask(task))
        init_task = pwndbg.aglib.kernel.init_task()
        task = int(init_task)
        if task not in seen:
            tasks.append(Ktask(task))
            seen.add(task)
        init_task = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", init_task)
        for task in for_each_entry(init_task["tasks"], "struct task_struct", "tasks"):
            if (task := int(task)) and task not in seen:
                seen.add(task)
                tasks.append(Ktask(task))
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR (get_ktasks): {e}"))
        return ()
    return tuple(tasks)


parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")
parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")
parser.add_argument("--pid", nargs="?", type=int, help="A pid to search for")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def ktask(task_name: str | None = None, pid: int | None = None) -> None:
    if not pwndbg.aglib.kernel.ktask.load_ktask_typeinfo():
        return
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
