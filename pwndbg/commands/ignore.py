"""
Ignoring a breakpoint
"""

import argparse

import gdb

import pwndbg.color.message as message
import pwndbg.commands

parser = argparse.ArgumentParser(
    description="""Set ignore-count of breakpoint, default to the last breakpoint number."""
)
parser.add_argument("bpnum", type=int, default=None, nargs="?", help="The breakpoint number N.")
parser.add_argument("count", type=int, help="The number to set COUNT.")

@pwndbg.commands.ArgparsedCommand(parser)
def ignore(bpnum, count):
    if bpnum is None:
        bpnum = max((bp.number for bp in gdb.breakpoints()), default=None)

    bp = next((bp for bp in gdb.breakpoints() if bp.number == bpnum), None)

    if bp is None:
        print(message.error("Breakpoint not found."))
        return

    bp.ignore_count = int(count)
