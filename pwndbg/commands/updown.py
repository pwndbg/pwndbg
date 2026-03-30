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

parser = argparse.ArgumentParser(description="Select and print stack frame that called this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go up."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def up(n=1) -> None:
    """
    Select and print stack frame that called this one.
    """
    f = gdb.selected_frame()

    for i in range(int(n)):
        if f.older():
            f = f.older()
    f.select()

    # workaround for #632
    gdb.execute("frame", to_string=True)

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
def down(n=1) -> None:
    """
    Select and print stack frame called by this one.
    """
    f = gdb.selected_frame()

    for i in range(int(n)):
        if f.newer():
            f = f.newer()
    f.select()

    # workaround for #632
    gdb.execute("frame", to_string=True)

    bt = pwndbg.commands.context.context_backtrace(with_banner=False)
    print("\n".join(bt))

    if pwndbg.commands.decompiler_integration.should_autojump:
        pwndbg.commands.decompiler_integration.auto_jump()
