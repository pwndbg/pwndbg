from __future__ import annotations

import argparse
import errno

import pwndbg.aglib.errno
import pwndbg.commands
import pwndbg.libc
from pwndbg.commands import CommandCategory

# Manually add error code 0 for "OK"
errno.errorcode[0] = "OK"  # type: ignore[index]

parser = argparse.ArgumentParser(
    description="Converts errno (or argument) to its string representation."
)
parser.add_argument(
    "err",
    type=int,
    nargs="?",
    default=None,
    help="Errno; if not passed, it is retrieved from __errno_location",
)


@pwndbg.commands.Command(parser, command_name="errno", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def errno_(err: int | None) -> None:
    if err is None:
        err, err_str = pwndbg.aglib.errno.get()
        if err_str != "":
            print(err_str)
            if pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN:
                print("Is the libc not loaded yet?")
            return

    msg = errno.errorcode.get(int(err), "Unknown error code")
    print(f"Errno {err}: {msg}")
