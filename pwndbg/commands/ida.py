from __future__ import annotations

import argparse
import bz2
import datetime
import os

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.gdblib.regs
import pwndbg.integration.ida
from pwndbg.commands import CommandCategory
from pwndbg.dbg import EventType
from pwndbg.gdblib.functions import GdbFunction


@pwndbg.commands.ArgparsedCommand(
    "Synchronize IDA's cursor with GDB.", category=CommandCategory.INTEGRATIONS
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.dbg.event_handler(EventType.STOP)
@pwndbg.integration.ida.withIDA
def j(*args) -> None:
    """
    Synchronize IDA's cursor with GDB
    """
    try:
        pc = int(gdb.selected_frame().pc())
        pwndbg.integration.ida.Jump(pc)
    except Exception:
        pass


parser = argparse.ArgumentParser(description="Select and print stack frame that called this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go up."
)


@pwndbg.commands.ArgparsedCommand(parser)
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

    j()


parser = argparse.ArgumentParser(description="Select and print stack frame called by this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go down."
)


@pwndbg.commands.ArgparsedCommand(parser)
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

    j()


@pwndbg.commands.ArgparsedCommand("Save the ida database.", category=CommandCategory.INTEGRATIONS)
@pwndbg.integration.ida.withIDA
def save_ida() -> None:
    """Save the IDA database"""
    if not pwndbg.integration.ida.available():
        return

    path = pwndbg.integration.ida.GetIdbPath()

    # Need to handle emulated paths for Wine
    if path.startswith("Z:"):
        path = path[2:].replace("\\", "/")
        pwndbg.integration.ida.SaveBase(path)

    basename = os.path.basename(path)
    dirname = os.path.dirname(path)
    backups = os.path.join(dirname, "ida-backup")

    if not os.path.isdir(backups):
        os.mkdir(backups)

    basename, ext = os.path.splitext(basename)
    basename += "-%s" % datetime.datetime.now().isoformat()
    basename += ext

    # Windows doesn't like colons in paths
    basename = basename.replace(":", "_")

    full_path = os.path.join(backups, basename)

    pwndbg.integration.ida.SaveBase(full_path)

    with open(full_path, "rb") as f:
        data = f.read()

    # Compress!
    full_path_compressed = full_path + ".bz2"
    bz2.BZ2File(full_path_compressed, "w").write(data)

    # Remove old version
    os.unlink(full_path)


save_ida()


@GdbFunction()
def ida(name):
    """Evaluate ida.LocByName() on the supplied value."""
    name = name.string()
    result = pwndbg.integration.ida.LocByName(name)

    if 0xFFFFE000 <= result <= 0xFFFFFFFF or 0xFFFFFFFFFFFFE000 <= result <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("ida.LocByName(%r) == BADADDR" % name)

    return result
