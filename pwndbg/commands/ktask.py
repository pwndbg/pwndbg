"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse
from typing import Tuple

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

parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")
parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")


class Kthread:
    def __init__(self, thread: pwndbg.dbg_mod.Value | int, cpu: int | None = None) -> None:
        thread = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", thread)
        self.thread = thread
        self.name = thread["comm"].string()
        self.pid = int(thread["pid"])
        self.has_user_page = int(thread["mm"]) != 0
        self.cpu = cpu
        self.uid = int(thread["cred"]["uid"]["val"])
        self.gid = int(thread["cred"]["gid"]["val"])

    @pwndbg.lib.cache.cache_until("stop")
    def files(self) -> Tuple[Tuple[int, pwndbg.dbg_mod.Value], ...]:
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
        if self.thread.dereference().type.has_field("stack"):
            return int(self.thread["stack"])
        # the offset of stack was not recovered
        return None

    def __str__(self) -> str:
        prefix = str(pwndbg.config.backtrace_prefix)
        if int(pwndbg.aglib.kernel.current_task()) != int(self.thread):
            prefix = " " * len(prefix)
        prefix = color.blue(prefix)
        thread = color.blue(hex(int(self.thread)))
        pid = f"[pid {self.pid}]"
        pid = color.blue(f"{pid:<11}")
        cpu = "[cpu: -]"  # not scheduled on a cpu
        if self.cpu is not None:
            cpu = f"[cpu: {self.cpu}]"
        cpulen = 7 + len(str(pwndbg.aglib.kernel.nproc() - 1))
        cpu = color.red(f"{cpu:<{cpulen}}")
        desc = " "
        namelen = pwndbg.aglib.kernel.ktask.TASK_COMM_LEN
        prefix = f"{prefix} {pid} {cpu} task @ {thread}: {self.name:<{namelen}}"
        user = "[user task]" if self.has_user_page else ""
        uid = f"[uid: {self.uid}]"
        gid = f"[gid: {self.gid}]"
        desc = color.red(f"{uid:<11} {gid:<11} {user}")
        return f"{prefix} {desc}"


class Ktask:
    def __init__(self, task: pwndbg.dbg_mod.Value | int, cpu: int | None = None) -> None:
        task = pwndbg.aglib.memory.get_typed_pointer("struct task_struct", task)
        self.task = task
        threads = []
        signal = task["signal"]
        # Iterate through all threads in the task_struct's thread list.
        for thread in for_each_entry(signal["thread_head"], "struct task_struct", "thread_node"):
            kthread = Kthread(thread, cpu)
            threads.append(kthread)
        self.threads = threads


@pwndbg.lib.cache.cache_until("stop")
def get_ktasks() -> Tuple[Ktask, ...]:
    if not pwndbg.aglib.kernel.ktask.load_ktask_typeinfo():
        return ()
    tasks: list[Ktask] = []
    try:
        seen = set()
        for i in range(0, pwndbg.aglib.kernel.nproc()):
            task = int(pwndbg.aglib.kernel.current_task(i))
            seen.add(task)
            tasks.append(Ktask(task, i))
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


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelSymbols
def ktask(task_name=None) -> None:
    if not pwndbg.aglib.kernel.ktask.load_ktask_typeinfo():
        return
    threads = []
    for task in get_ktasks():
        for thread in task.threads:
            if task_name is not None and task_name not in thread.name:
                continue
            threads.append(thread)
    threads.sort(key=lambda thread: (thread.pid, thread.name))
    indent = IndentContextManager()
    for thread in threads:
        indent.print(thread)
