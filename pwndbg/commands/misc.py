import argparse
import errno

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.gdblib.arch as _arch
import pwndbg.regs
import pwndbg.symbol

errno.errorcode[0] = "OK"

parser = argparse.ArgumentParser(
    description="""
Converts errno (or argument) to its string representation.
"""
)
parser.add_argument(
    "err",
    type=int,
    nargs="?",
    default=None,
    help="Errno; if not passed, it is retrieved from __errno_location",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="errno")
@pwndbg.commands.OnlyWhenRunning
def errno_(err):
    if err is None:
        # Try to get the `errno` variable value
        # if it does not exist, get the errno variable from its location
        try:
            err = int(gdb.parse_and_eval("errno"))
        except gdb.error:
            try:
                # We can't simply call __errno_location because its .plt.got entry may be uninitialized
                # (e.g. if the binary was just started with `starti` command)
                # So we have to check the got.plt entry first before calling it
                errno_loc_gotplt = pwndbg.symbol.address("__errno_location@got.plt")

                # If the got.plt entry is not there (is None), it means the symbol is not used by the binary
                if errno_loc_gotplt is None or pwndbg.vmmap.find(
                    pwndbg.memory.pvoid(errno_loc_gotplt)
                ):
                    err = int(gdb.parse_and_eval("*((int *(*) (void)) __errno_location) ()"))
                else:
                    print(
                        "Could not determine error code automatically: the __errno_location@got.plt has no valid address yet (perhaps libc.so hasn't been loaded yet?)"
                    )
                    return
            except gdb.error:
                print(
                    "Could not determine error code automatically: neither `errno` nor `__errno_location` symbols were provided (perhaps libc.so hasn't been not loaded yet?)"
                )
                return

    msg = errno.errorcode.get(int(err), "Unknown error code")
    print("Errno %s: %s" % (err, msg))


parser = argparse.ArgumentParser(
    description="""
Prints out a list of all pwndbg commands. The list can be optionally filtered if filter_pattern is passed.
"""
)
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to commands names/docs",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="pwndbg")
def pwndbg_(filter_pattern):
    for name, docs in list_and_filter_commands(filter_pattern):
        print("%-20s %s" % (name, docs))


parser = argparse.ArgumentParser(description="""Print the distance between the two arguments.""")
parser.add_argument("a", type=int, help="The first address.")
parser.add_argument("b", type=int, help="The second address.")


@pwndbg.commands.ArgparsedCommand(parser)
def distance(a, b):
    """Print the distance between the two arguments"""
    a = int(a) & pwndbg.arch.ptrmask
    b = int(b) & pwndbg.arch.ptrmask

    distance = b - a

    print("%#x->%#x is %#x bytes (%#x words)" % (a, b, distance, distance // pwndbg.arch.ptrsize))


def list_and_filter_commands(filter_str):
    sorted_commands = list(pwndbg.commands.commands)
    sorted_commands.sort(key=lambda x: x.__name__)

    if filter_str:
        filter_str = filter_str.lower()

    results = []

    for c in sorted_commands:
        name = c.__name__
        docs = c.__doc__

        if docs:
            docs = docs.strip()
        if docs:
            docs = docs.splitlines()[0]

        if not filter_str or filter_str in name.lower() or (docs and filter_str in docs.lower()):
            results.append((name, docs))

    return results
