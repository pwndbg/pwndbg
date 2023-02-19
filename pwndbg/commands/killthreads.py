import argparse
from typing import List
from typing import Optional

import gdb

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.scheduler import lock_scheduler

parser = argparse.ArgumentParser(description="Kill multiple threads at once.")

parser.add_argument("thread_ids", nargs="*", help="Thread IDs to kill.")
parser.add_argument(
    "-a", "--all", action="store_true", help="Kill all threads except the current one."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.PROCESS)
@pwndbg.commands.OnlyWhenRunning
def killthreads(thread_ids: Optional[List] = None, all: bool = False) -> None:
    if len(thread_ids) == 0 and not all:
        print(message.error("No thread IDs specified and --all not set"))
        return

    if all and len(thread_ids) > 0:
        print(message.error("Cannot specify thread IDs and --all"))
        return

    with lock_scheduler():
        current_thread_id = gdb.selected_thread().num
        if all:
            thread_ids = [
                thread.num
                for thread in gdb.selected_inferior().threads()
                if thread.num != current_thread_id
            ]
        for thread_id in thread_ids:
            gdb.execute(f"thread {thread_id}")
            try:
                gdb.execute("call (void) pthread_exit(0)")
            except gdb.error as e:
                # gdb will throw an error, because the thread dies during the call, which is expected
                if (
                    "The program being debugged stopped while in a function called from GDB."
                    not in str(e)
                ):
                    raise e
                pass

        # Switch back to the thread we were on before killing threads
        gdb.execute(f"thread {current_thread_id}")
        if len(thread_ids) == 1:
            print(message.success("Killed 1 thread"))
        else:
            print(message.success(f"Killed {len(thread_ids)} threads"))
