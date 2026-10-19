"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.commands
from pwndbg.lib.exception import IndentContextManager

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
    for task in pwndbg.aglib.kernel.ktask.get_ktasks():
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
