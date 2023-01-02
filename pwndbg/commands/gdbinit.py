"""
Compatibility functionality for GDBINIT users.

https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
"""

import gdb

import pwndbg.commands


@pwndbg.commands.ArgparsedCommand(
    "GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."
)
@pwndbg.commands.OnlyWhenRunning
def sstart() -> None:
    """GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."""
    gdb.execute("tbreak __libc_start_main")
    gdb.execute("run")


@pwndbg.commands.ArgparsedCommand(
    "GDBINIT compatibility alias to print the entry point. See also the 'entry' command.",
)
@pwndbg.commands.OnlyWhenRunning
def entry_point() -> None:
    """GDBINIT compatibility alias to print the entry point.
    See also the 'entry' command."""
    print(hex(int(pwndbg.gdblib.elf.entry())))
