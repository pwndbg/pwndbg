"""
Displays information about kernel tasks. This command iterates through the kernel's task list
and prints details about each task, including its address, PID, user space status, CPU, UID, GID, and name.
"""

from __future__ import annotations

import argparse

import pwndbg.color.message as message
import pwndbg.commands
from pwndbg.aglib.kernel.macros import container_of

parser = argparse.ArgumentParser(description="Displays information about kernel tasks.")

parser.add_argument("task_name", nargs="?", type=str, help="A task name to search for")


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
@pwndbg.commands.OnlyWithKernelDebugInfo
def ktask(task_name=None) -> None:
    print(f"{'Address':>18} {'PID':>6} {'User':>4} {'CPU':>4} {'UID':>4} {'GID':>4} {'Name'}")

    # Look up the init_task symbol, which is the first task in the kernel's task list.
    init_task = pwndbg.aglib.symbol.lookup_symbol_addr("init_task")
    if init_task is None:
        print(
            "The init_task symbol was not found. This may indicate that the symbol is not available in the current build."
        )
        return

    curr_task = init_task

    try:
        # The task list is implemented a circular doubly linked list, so we traverse starting from init_task.
        while True:
            task_struct = pwndbg.aglib.memory.get_typed_pointer_value(
                "struct task_struct", curr_task
            )
            thread_head = task_struct["signal"]["thread_head"]

            curr_thread = thread_head["next"]

            # Iterate through all threads in the task_struct's thread list.
            while True:
                if int(thread_head.address) == int(curr_thread):
                    break

                thread = container_of(int(curr_thread), "struct task_struct", "thread_node")

                task_struct2 = pwndbg.aglib.memory.get_typed_pointer_value(
                    "struct task_struct", thread
                )

                comm = task_struct2["comm"].string()

                # Print task information if no specific task name is provided or if the current task matches the provided name.
                if not task_name or task_name in comm:
                    curr_task_hex = hex(curr_task)
                    pid = int(task_struct2["pid"])
                    user = "✓" if int(task_struct2["mm"]) != 0 else "✗"
                    cpu = int(task_struct2["thread_info"]["cpu"])

                    # Get UID and GID from the credentials structure
                    uid = int(task_struct2["real_cred"]["uid"]["val"])
                    gid = int(task_struct2["real_cred"]["gid"]["val"])

                    print(
                        f"{curr_task_hex:>18} {pid:>6} {user:>4} {cpu:>4} {uid:>6} {gid:>6} {comm:<7}"
                    )

                curr_thread = curr_thread["next"]

            next_task = container_of(
                int(task_struct["tasks"]["next"]), "struct task_struct", "tasks"
            )

            if int(next_task) == init_task:
                break

            curr_task = int(next_task)

    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return
