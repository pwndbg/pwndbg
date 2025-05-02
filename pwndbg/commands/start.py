"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""

from __future__ import annotations

import argparse
from shlex import quote

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.elf
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.dbg
from pwndbg.commands import CommandCategory
from pwndbg.dbg import BreakpointLocation
from pwndbg.dbg import DebuggerType

if pwndbg.dbg.is_gdblib_available():
    import gdb


def breakpoint_at_entry():
    addr = int(pwndbg.aglib.elf.entry())
    if not addr:
        print(M.error("No entry address found for the binary."))
        return

    if int(pwndbg.aglib.regs.pc) == addr:
        # Skip setting the breakpoint because we are already at the entry point.
        # This occurs when execution started with `starti` or `run -s`.
        return

    proc = pwndbg.dbg.selected_inferior()
    bp = proc.break_at(BreakpointLocation(addr), internal=True)

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        with bp:
            await ec.cont(bp)

    proc.dispatch_execution_controller(ctrl)


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
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


@pwndbg.commands.Command(
    parser,
    aliases=["main", "init"],
    only_debuggers={DebuggerType.GDB},
    category=CommandCategory.START,
)
@pwndbg.commands.OnlyWhenLocal
def start(args=None) -> None:
    if args is None:
        args = []
    run = "run " + " ".join(args)

    symbols = ["main", "_main", "start", "_start", "init", "_init"]

    for symbol in symbols:
        address = pwndbg.aglib.symbol.lookup_symbol_addr(symbol)
        if not address:
            continue

        gdb.Breakpoint(symbol, temporary=True)
        gdb.execute(run, from_tty=False)
        return

    # Try a breakpoint at the binary entry
    entry(args)


# Starting from 3rd paragraph, the description is
# taken from the GDB's `starti` command description
parser = argparse.ArgumentParser(
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
    "args", nargs="*", type=str, default=None, help="The arguments to run the binary with."
)


@pwndbg.commands.Command(parser, category=CommandCategory.START)
@pwndbg.commands.OnlyWithFile
@pwndbg.commands.OnlyWhenLocal
def entry(args=None) -> None:
    if args is None:
        args = []

    if pwndbg.dbg.is_gdblib_available():
        run = "starti " + " ".join(map(quote, args))
        gdb.execute(run, from_tty=False)
    else:
        # TODO: LLDB, In the future, we should handle `run -s` here to automate setup.
        # For now, we only support stopping at the entry breakpoint.
        if not pwndbg.aglib.proc.alive:
            print(
                M.error(
                    "The program is not running. Start the program with `run -s` and then use `entry` to set the breakpoint."
                )
            )
            return
    breakpoint_at_entry()


@pwndbg.commands.Command(
    "Alias for 'tbreak __libc_start_main; run'.",
    only_debuggers={DebuggerType.GDB},
    category=CommandCategory.START,
)
@pwndbg.commands.OnlyWithFile
@pwndbg.commands.OnlyWhenLocal
def sstart() -> None:
    gdb.Breakpoint("__libc_start_main", temporary=True)
    gdb.execute("run")
