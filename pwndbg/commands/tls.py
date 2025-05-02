"""
Command to print the information of the current Thread Local Storage (TLS).
"""

from __future__ import annotations

import argparse

from tabulate import tabulate

import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.tls
import pwndbg.aglib.vmmap
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.dbg
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Print out base address of the current Thread Local Storage (TLS).",
)

parser.add_argument(
    "-p",
    "--pthread-self",
    action="store_true",
    default=False,
    help="Try to get the address of TLS by calling pthread_self().",
)

parser.add_argument("-a", "--all", action="store_true", help="Do not truncate the dump output.")


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def tls(pthread_self=False, all: bool = False) -> None:
    tls_base = (
        pwndbg.aglib.tls.find_address_with_register()
        if not pthread_self
        else pwndbg.aglib.tls.find_address_with_pthread_self()
    )
    if pwndbg.aglib.memory.is_readable_address(tls_base):
        print(message.success("Thread Local Storage (TLS) base: %#x" % tls_base))
        print(message.success("TLS is located at:"))
        print(message.notice(pwndbg.aglib.vmmap.find(tls_base)))

        # Displaying `dt tcbhead_t <tls_base>` if possible
        # If not, we will dump the tls with telescope
        output = str(pwndbg.aglib.dt.dt("tcbhead_t", addr=tls_base))

        print(message.success("Dumping the address:"))
        if output == "Type not found.":
            pwndbg.commands.telescope.telescope(tls_base, 10)
        else:
            lines = output.splitlines()

            if all or len(lines) <= 10:
                print(message.notice(output))
            else:
                index = None
                for i, line in enumerate(lines):
                    if "__glibc_unused2" in line:
                        index = i
                        break

                if index is not None:
                    end_index = index + 2
                    for line in lines[:end_index]:
                        print(message.notice(line))
                    print(message.notice("\t[...]"))
                    print(
                        message.hint(
                            "Output truncated. Rerun with option -a to display the full output."
                        )
                    )
                # In case there is a tcbhead_t but there is no __glibc_unused2
                else:
                    for line in lines[:10]:
                        print(message.notice(line))
                    print(message.notice("\t[...]"))
                    print(
                        message.hint(
                            "Output truncated. Rerun with option -a to display the full output."
                        )
                    )
        return
    print(message.error("Couldn't find Thread Local Storage (TLS) base."))
    if not pthread_self:
        print(
            message.notice(
                "You can try to use -p/--pthread option to get the address of TLS by calling pthread_self().\n"
                "(This might cause problems if the pthread_self() is not in libc or not initialized yet.)"
            )
        )


parser = argparse.ArgumentParser(
    description="List all threads belonging to the selected inferior.",
)
group = parser.add_mutually_exclusive_group()

group.add_argument(
    "num_threads",
    type=int,
    nargs="?",
    default=None,
    help="Number of threads to display. Omit to display all threads.",
)

group.add_argument(
    "-c",
    "--config",
    action="store_true",
    dest="respect_config",
    help="Respect context-max-threads config to limit number of threads displayed.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def threads(num_threads, respect_config) -> None:
    table = []
    headers = ["global_num", "name", "status", "pc", "symbol"]
    bold_green = lambda text: pwndbg.color.bold(pwndbg.color.green(text))

    import gdb

    try:
        original_thread = gdb.selected_thread()
    except SystemError:
        original_thread = None
    try:
        original_frame = gdb.selected_frame()
    except gdb.error:
        original_frame = None

    all_threads = gdb.selected_inferior().threads()[::-1]

    displayed_threads = []

    if original_thread is not None and original_thread.is_valid():
        displayed_threads.append(original_thread)

    for thread in all_threads:
        if respect_config and len(displayed_threads) >= int(
            pwndbg.commands.context.config_max_threads_display
        ):
            break

        if num_threads is not None and len(displayed_threads) >= num_threads:
            break

        if thread.is_valid() and thread is not original_thread:
            displayed_threads.append(thread)

    for thread in displayed_threads:
        name = thread.name or ""

        if thread is original_thread:
            row = [
                bold_green(thread.global_num),
                bold_green(name),
            ]
        else:
            row = [
                str(thread.global_num),
                name,
            ]

        row.append(pwndbg.commands.context.get_thread_status(thread))

        if thread.is_stopped():
            thread.switch()
            pc = pwndbg.dbg.selected_frame().pc()

            pc_colored = M.get(pc)
            symbol = pwndbg.aglib.symbol.resolve_addr(pc)

            row.append(pc_colored)

            if symbol:
                if thread is original_thread:
                    row.append(bold_green(symbol))
                else:
                    row.append(symbol)

        table.append(row)

    if original_thread is not None and original_thread.is_valid():
        original_thread.switch()
    if original_frame is not None and original_frame.is_valid():
        original_frame.select()

    print(tabulate(table, headers))
    print(f"\nShowing {len(displayed_threads)} of {len(all_threads)} threads.")
