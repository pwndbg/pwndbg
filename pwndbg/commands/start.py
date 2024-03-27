"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""

from __future__ import annotations

import argparse
from argparse import RawTextHelpFormatter
from shlex import quote

import gdb

import pwndbg.commands
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.symbol
from pwndbg.commands import CommandCategory

break_on_first_instruction = False


@pwndbg.gdblib.events.start
def on_start() -> None:
    global break_on_first_instruction
    if break_on_first_instruction:
        spec = "*%#x" % (int(pwndbg.gdblib.elf.entry()))
        gdb.Breakpoint(spec, temporary=True)
        break_on_first_instruction = False


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
    formatter_class=RawTextHelpFormatter,
    description="""
Start the debugged program stopping at the first convenient location
from this list: main, _main, start, _start, init or _init.
You may specify arguments to give it.

Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".
""",
)

parser.add_argument(
    "args", nargs="*", type=str, default=None, help="The arguments to run the binary with."
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["main", "init"], category=CommandCategory.START)
def start(args=None) -> None:
    if args is None:
        args = []
    run = "run " + " ".join(args)

    symbols = ["main", "_main", "start", "_start", "init", "_init"]

    for symbol in symbols:
        address = pwndbg.gdblib.symbol.address(symbol)

        if not address:
            continue

        gdb.Breakpoint(symbol, temporary=True)
        gdb.execute(run, from_tty=False, to_string=True)
        return

    # Try a breakpoint at the binary entry
    entry(args)


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
    formatter_class=RawTextHelpFormatter,
    description="""
Start the debugged program stopping at its entrypoint address.

Note that the entrypoint may not be the first instruction executed
by the program. If you want to stop on the first executed instruction,
use the GDB's `starti` command.

Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".
""",
)
parser.add_argument(
    "args", nargs="*", type=str, default=[], help="The arguments to run the binary with."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.START)
@pwndbg.commands.OnlyWithFile
def entry(args=[]) -> None:
    global break_on_first_instruction
    break_on_first_instruction = True
    run = "run " + " ".join(map(quote, args))
    gdb.execute(run, from_tty=False)


@pwndbg.commands.ArgparsedCommand(
    "Alias for 'tbreak __libc_start_main; run'.", category=CommandCategory.START
)
@pwndbg.commands.OnlyWithFile
def sstart() -> None:
    gdb.Breakpoint("__libc_start_main", temporary=True)
    gdb.execute("run")
