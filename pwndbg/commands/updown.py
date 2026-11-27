"""
Overrides GDB's up and down commands to be prettier and to follow
the decompiler integration.
"""

from __future__ import annotations

import argparse

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.decompiler_integration
from pwndbg.commands import CommandCategory


def _select_frame(f: gdb.Frame) -> None:
    """
    Select `f` the same way GDB's own `up`/`down` would.

    `gdb.Frame.select()` alone does not update the current source line used by
    `list` (see #632), so we also run `frame`. By default `frame` prints the
    frame's source line, which makes GDB open (or, with debuginfod, try to
    download) the source file every time. For frames in libraries without local
    sources (libc, libstdc++, ...) this made `up`/`down` take hundreds of
    milliseconds each (#4186). We throw that output away anyway, so ask GDB to
    print only the location instead.
    """
    f.select()

    old_frame_info = gdb.parameter("print frame-info")
    gdb.execute("set print frame-info short-location", to_string=True)
    try:
        gdb.execute("frame", to_string=True)
    finally:
        gdb.execute(f"set print frame-info {old_frame_info}", to_string=True)


parser = argparse.ArgumentParser(description="Select and print stack frame that called this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go up."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def up(n: int = 1) -> None:
    """
    Select and print stack frame that called this one.
    """
    f = gdb.selected_frame()

    for _ in range(int(n)):
        if f.older():
            f = f.older()
    _select_frame(f)

    bt = pwndbg.commands.context.context_backtrace(with_banner=False)
    print("\n".join(bt))

    if pwndbg.commands.decompiler_integration.should_autojump:
        pwndbg.commands.decompiler_integration.auto_jump()


parser = argparse.ArgumentParser(description="Select and print stack frame called by this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go down."
)


# Since we are redefining a gdb command, we also redefine the original aliases.
# These aliases ("do", "dow") are necessary to ensure consistency in the help system
# and to pass the test_consistent_help test, which verifies that all commands and their
# aliases are documented correctly. See issue #2961 for more details.
@pwndbg.commands.Command(parser, category=CommandCategory.MISC, aliases=["do", "dow"])
@pwndbg.commands.OnlyWhenRunning
def down(n: int = 1) -> None:
    """
    Select and print stack frame called by this one.
    """
    f = gdb.selected_frame()

    for _ in range(n):
        if f.newer():
            f = f.newer()
    _select_frame(f)

    bt = pwndbg.commands.context.context_backtrace(with_banner=False)
    print("\n".join(bt))

    if pwndbg.commands.decompiler_integration.should_autojump:
        pwndbg.commands.decompiler_integration.auto_jump()
