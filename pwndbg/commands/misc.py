import argparse
import errno

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol

errno.errorcode[0] = "OK"  # type: ignore # manually add error code 0 for "OK"

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
                errno_loc_gotplt = pwndbg.gdblib.symbol.address("__errno_location@got.plt")

                # If the got.plt entry is not there (is None), it means the symbol is not used by the binary
                if errno_loc_gotplt is None or pwndbg.gdblib.vmmap.find(
                    pwndbg.gdblib.memory.pvoid(errno_loc_gotplt)
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

group = parser.add_mutually_exclusive_group()
group.add_argument("--shell", action="store_true", help="Only display shell commands")
group.add_argument("--all", dest="all_", action="store_true", help="Only display shell commands")

parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to commands names/docs",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="pwndbg")
def pwndbg_(filter_pattern, shell, all_):
    if all_:
        shell_cmds = True
        pwndbg_cmds = True
    elif shell:
        shell_cmds = True
        pwndbg_cmds = False
    else:
        shell_cmds = False
        pwndbg_cmds = True

    for name, docs in list_and_filter_commands(filter_pattern, pwndbg_cmds, shell_cmds):
        print("%-20s %s" % (name, docs))


parser = argparse.ArgumentParser(description="""Print the distance between the two arguments.""")
parser.add_argument("a", type=int, help="The first address.")
parser.add_argument("b", type=int, help="The second address.")


@pwndbg.commands.ArgparsedCommand(parser)
def distance(a, b):
    """Print the distance between the two arguments"""
    a = int(a) & pwndbg.gdblib.arch.ptrmask
    b = int(b) & pwndbg.gdblib.arch.ptrmask

    distance = b - a

    print(
        "%#x->%#x is %#x bytes (%#x words)"
        % (a, b, distance, distance // pwndbg.gdblib.arch.ptrsize)
    )


def list_and_filter_commands(filter_str, pwndbg_cmds=True, shell_cmds=False):
    sorted_commands = list(pwndbg.commands.commands)
    sorted_commands.sort(key=lambda x: x.__name__)

    if filter_str:
        filter_str = filter_str.lower()

    results = []

    for c in sorted_commands:
        # If this is a shell command and we didn't ask for shell commands, skip it
        if c.shell and not shell_cmds:
            continue

        # If this is a normal command and we didn't ask for normal commands, skip it
        if not c.shell and not pwndbg_cmds:
            continue

        name = c.__name__
        docs = c.__doc__

        if docs:
            docs = docs.strip()
        if docs:
            docs = docs.splitlines()[0]

        if not filter_str or filter_str in name.lower() or (docs and filter_str in docs.lower()):
            results.append((name, docs))

    return results
