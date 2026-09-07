from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.scheduler import lock_scheduler

parser = argparse.ArgumentParser(
    description="""Kill all or given threads.

Switches to given threads and calls pthread_exit(0) on them.
This is performed with scheduler-locking to prevent other threads from operating at the same time.

Killing all other threads may be useful to use GDB checkpoints, e.g., to test given input & restart the execution to the point of interest (checkpoint).
""",
)

parser.add_argument("thread_ids", type=int, nargs="*", help="Thread IDs to kill.")
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="Kill all threads except the current one.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.PROCESS)
@pwndbg.commands.OnlyWhenRunning
def killthreads(thread_ids: list[int] | None = None, all: bool = False) -> None:
    if thread_ids is None or len(thread_ids) == 0 and not all:
        print(message.error("No thread IDs or --all flag specified"))
        return

    if all and len(thread_ids) > 0:
        print(message.error("Cannot specify thread IDs and --all"))
        return

    with lock_scheduler():
        current_thread_id = gdb.selected_thread().num
        available_thread_ids = [
            thread.num
            for thread in gdb.selected_inferior().threads()
            if thread.num != current_thread_id
        ]
        if all:
            thread_ids = available_thread_ids
        else:
            for thread_id in thread_ids:
                if thread_id not in available_thread_ids:
                    print(
                        message.error(f"Thread ID {thread_id} does not exist, see `info threads`")
                    )
                    return
        killed = []
        for thread_id in thread_ids:
            gdb.execute(f"thread {thread_id}", to_string=True)
            error = None
            try:
                gdb.execute("call (void) pthread_exit(0)", to_string=True)
            except gdb.error as e:
                error = e

            # The call is always reported as aborted, both when the thread died inside it
            # and when something else stopped the inferior first, so only the thread list
            # tells us whether the kill worked.
            if any(thread.num == thread_id for thread in gdb.selected_inferior().threads()):
                print(message.error(f"Failed to kill thread {thread_id}: {error}"))
            else:
                killed.append(thread_id)

        # Switch back to the thread we were on before killing threads
        gdb.execute(f"thread {current_thread_id}", to_string=True)
        if killed:
            print(
                message.success(
                    "Killed threads with IDs: " + ", ".join(str(thread_id) for thread_id in killed)
                )
            )
