"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry

parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")

parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")


class Kthread:
    def __init__(self, thread: pwndbg.dbg_mod.Value):
        self.thread = thread
        self.name = thread["comm"].string()
        self.pid = int(thread["pid"])
        self.is_user = int(thread["mm"]) != 0
        self.cpu = int(thread["thread_info"]["cpu"])
        self.uid = int(thread["real_cred"]["uid"]["val"])
        self.gid = int(thread["real_cred"]["gid"]["val"])

    def __str__(self):
        t = self
        user = "✓" if t.is_user else "✗"
        return f"{t.pid:>6} {user:>4} {t.cpu:>4} {t.uid:>6} {t.gid:>6} {t.name}"


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

    def print_threads(self, name):
        for t in self.threads:
            if name is not None and name not in t.name:
                continue
            task = hex(int(self.task))
            print(f"{task:>18} {t}")


# TODO: cache?
def get_ktasks():
    tasks = []
    # Look up the init_task symbol, which is the first task in the kernel's task list.
    init_task = pwndbg.aglib.symbol.lookup_symbol("init_task")
    if init_task is None:
        print(
            "The init_task symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return None

    try:
        # The task list is implemented a circular doubly linked list, so we traverse starting from init_task.
        for task in for_each_entry(init_task["tasks"], "struct task_struct", "tasks"):
            ktask = Ktask(task)
            tasks.append(ktask)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return None
    return tasks


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSymbols
def ktask(task_name=None) -> None:
    print(f"{'Address':>18} {'PID':>6} {'User':>4} {'CPU':>4} {'UID':>4} {'GID':>4} {'Name'}")
    for ktask in get_ktasks():
        ktask.print_threads(task_name)
