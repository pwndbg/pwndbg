"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse
from typing import Tuple

import pwndbg.aglib.kernel
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

indent = IndentContextManager()


class Kthread:
    def __init__(self, thread: pwndbg.dbg_mod.Value):
        self.thread = thread
        self.name = thread["comm"].string()
        self.pid = int(thread["pid"])
        self.has_user_page = int(thread["mm"]) != 0
        krelease = pwndbg.aglib.kernel.krelease()
        if krelease is None or "CONFIG_THREAD_INFO_IN_TASK" not in pwndbg.aglib.kernel.kconfig():
            self.cpu = "-"
        elif krelease < (5, 16):
            self.cpu = int(thread["cpu"])
        else:
            self.cpu = int(thread["thread_info"]["cpu"])
        self.uid = int(thread["real_cred"]["uid"]["val"])
        self.gid = int(thread["real_cred"]["gid"]["val"])

    @pwndbg.lib.cache.cache_until("stop")
    def files(self):
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
    def mm(self):
        mm = self.thread["mm"]
        if int(mm) != 0:
            return mm
        # for anonymous tasks
        mm = self.thread["active_mm"]
        if int(mm) != 0:
            return mm
        return None

    def __str__(self):
        thread = color.blue(hex(int(self.thread)))
        prefix = f"[pid {self.pid}]"
        desc = " "
        prefix = color.blue(f"{prefix:<9}") + f"task @ {thread}: {self.name:<16}"
        user = ", has user pages" if self.has_user_page else ""
        desc = color.red(f"cpu #{self.cpu} (uid: {self.uid}, gid: {self.gid}{user})")
        return f"{prefix} {desc}"


class Ktask:
    def __init__(self, task: pwndbg.dbg_mod.Value):
        self.task = task
        threads = []
        signal = task["signal"]
        # Iterate through all threads in the task_struct's thread list.
        for thread in for_each_entry(signal["thread_head"], "struct task_struct", "thread_node"):
            kthread = Kthread(thread)
            threads.append(kthread)
        self.threads = threads


@pwndbg.lib.cache.cache_until("stop")
def get_ktasks() -> Tuple[Ktask, ...]:
    tasks = []
    # Look up the init_task symbol, which is the first task in the kernel's task list.
    init_task = pwndbg.aglib.symbol.lookup_symbol("init_task")
    if init_task is None:
        print(
            "The init_task symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return None

    try:
        tasks.append(Ktask(init_task))
        # The task list is implemented a circular doubly linked list, so we traverse starting from init_task.
        for task in for_each_entry(init_task["tasks"], "struct task_struct", "tasks"):
            ktask = Ktask(task)
            tasks.append(ktask)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return None
    return tuple(tasks)


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def ktask(task_name=None) -> None:
    threads = []
    for task in get_ktasks():
        for thread in task.threads:
            if task_name is not None and task_name not in thread.name:
                continue
            threads.append(thread)
    for thread in threads:
        indent.print(thread)
