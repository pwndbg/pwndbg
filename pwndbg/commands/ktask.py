"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse

from tabulate import tabulate

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.aglib.kernel.macros import for_each_entry

parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")

parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugSymbols
def ktask(task_name=None) -> None:
    headers = ["Address", "pid", "user", "cpu", "uid", "gid", "name"]
    threads = []

    # Look up the init_task symbol, which is the first task in the kernel's task list.
    init_task = pwndbg.aglib.symbol.lookup_symbol("init_task")
    if init_task is None:
        print(
            "The init_task symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    try:
        # The task list is implemented a circular doubly linked list, so we traverse starting from init_task.
        for curr_task in for_each_entry(init_task["tasks"], "struct task_struct", "tasks"):
            task_struct = pwndbg.aglib.memory.get_typed_pointer_value(
                "struct task_struct", curr_task
            )
            signal = task_struct["signal"]

            # Iterate through all threads in the task_struct's thread list.
            for thread in for_each_entry(
                signal["thread_head"], "struct task_struct", "thread_node"
            ):
                comm = thread["comm"].string()
                # Print task information if no specific task name is provided or if the current task matches the provided name.
                if not task_name or task_name in comm:
                    curr_task_hex = hex(int(curr_task))
                    pid = int(thread["pid"])
                    user = "✓" if int(thread["mm"]) != 0 else "✗"
                    cpu = int(thread["thread_info"]["cpu"])

                    # Get UID and GID from the credentials structure
                    uid = int(thread["real_cred"]["uid"]["val"])
                    gid = int(thread["real_cred"]["gid"]["val"])
                    # TODO: encapsule them in a class
                    threads.append([curr_task_hex, pid, user, cpu, uid, gid, comm])
        print(tabulate(threads, headers))
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return
