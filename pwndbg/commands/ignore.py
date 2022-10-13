"""
Ignoring a breakpoint
"""

import argparse

import gdb

import pwndbg.color.message as message
import pwndbg.commands

parser = argparse.ArgumentParser()
parser.description = """Set ignore-count of breakpoint number N to COUNT.

While the ignore count is positive, execution will not stop on the breakpoint.

By default, if `N' is ommitted, the last breakpoint (i.e. greatest breakpoint number) will be used."""
parser.formatter_class = argparse.RawDescriptionHelpFormatter
parser.add_argument(
    "bpnum", metavar="N", type=int, default=None, nargs="?", help="The breakpoint number N."
)
parser.add_argument("count", metavar="COUNT", type=int, help="The number to set COUNT.")


@pwndbg.commands.ArgparsedCommand(parser)
def ignore(bpnum, count):
    bps = gdb.breakpoints()

    if not bps:
        print(message.error("No breakpoints set."))
        return

    if bpnum is None:
        bp = max(bps, key=lambda bp: bp.number)
    else:
        bp = next((bp for bp in bps if bp.number == bpnum), None)

        if bp is None:
            print(message.error("No breakpoint number %d." % bpnum))
            return

    count = max(0, int(count))
    bp.ignore_count = count
    print("Will ignore next %d crossings of breakpoint %d." % (count, bp.number))
