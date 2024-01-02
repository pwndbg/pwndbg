"""
Command to print the information of the current Thread Local Storage (TLS).
"""
from __future__ import annotations

import argparse

import gdb
from tabulate import tabulate

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.tls
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="Print out base address of the current Thread Local Storage (TLS).",
)

parser.add_argument(
    "-p",
    "--pthread-self",
    action="store_true",
    default=False,
    help="Try to get the address of TLS by calling pthread_self().",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def tls(pthread_self=False) -> None:
    tls_base = (
        pwndbg.gdblib.tls.find_address_with_register()
        if not pthread_self
        else pwndbg.gdblib.tls.find_address_with_pthread_self()
    )
    if pwndbg.gdblib.memory.is_readable_address(tls_base):
        print(message.success("Thread Local Storage (TLS) base: %#x" % tls_base))
        print(message.success("TLS is located at:"))
        print(message.notice(pwndbg.gdblib.vmmap.find(tls_base)))
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
    formatter_class=argparse.RawTextHelpFormatter,
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


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def threads(num_threads, respect_config) -> None:
    table = []
    headers = ["global_num", "name", "status", "pc", "symbol"]
    bold_green = lambda text: pwndbg.color.bold(pwndbg.color.green(text))

    try:
        original_thread = gdb.selected_thread()
    except SystemError:
        original_thread = None

    all_threads = gdb.selected_inferior().threads()[::-1]

    displayed_threads = []

    if original_thread is not None and original_thread.is_valid():
        displayed_threads.append(original_thread)

    for thread in all_threads:
        if respect_config and len(displayed_threads) >= int(
            pwndbg.commands.context.config_max_threads_display
        ):
            break
        elif num_threads is not None and len(displayed_threads) >= num_threads:
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
            pc = gdb.selected_frame().pc()

            pc_colored = M.get(pc)
            symbol = pwndbg.gdblib.symbol.get(pc)

            row.append(pc_colored)

            if symbol:
                if thread is original_thread:
                    row.append(bold_green(symbol))
                else:
                    row.append(symbol)

        table.append(row)

    if original_thread is not None and original_thread.is_valid():
        original_thread.switch()

    print(tabulate(table, headers))
    print(f"\nShowing {len(displayed_threads)} of {len(all_threads)} threads.")
