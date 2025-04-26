from __future__ import annotations

import argparse
import bz2
import datetime
import os

import gdb

import pwndbg
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.dbg
import pwndbg.integration.ida
from pwndbg.commands import CommandCategory
from pwndbg.dbg import EventType
from pwndbg.gdblib.functions import GdbFunction


@pwndbg.commands.Command(
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
        pc = int(pwndbg.dbg.selected_frame().pc())
        pwndbg.integration.ida.Jump(pc)
    except Exception:
        pass


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

    j()


parser = argparse.ArgumentParser(description="Select and print stack frame called by this one.")
parser.add_argument(
    "n", nargs="?", default=1, type=int, help="The number of stack frames to go down."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
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


@pwndbg.commands.Command("Save the ida database.", category=CommandCategory.INTEGRATIONS)
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


def _ida_local(name: str) -> int | None:
    if not pwndbg.aglib.proc.alive:
        return None

    pc = int(pwndbg.dbg.selected_frame().pc())
    frame_id = pwndbg.integration.ida.GetFuncAttr(pc, pwndbg.integration.ida.idc.FUNCATTR_FRAME)  # type: ignore[attr-defined]
    if frame_id == -1:
        return None

    stack_size = pwndbg.integration.ida.GetStrucSize(frame_id)

    # workaround for bug in IDA 9 when looking up the " s" member offset raises
    # AttributeError: module 'ida_typeinf' has no attribute 'FRAME_UDM_NAME_S'
    saved_baseptr = pwndbg.integration.ida.GetMemberOffset(frame_id, "__saved_registers")
    if saved_baseptr == -1:
        saved_baseptr = pwndbg.integration.ida.GetMemberOffset(frame_id, " s")

    for i in range(stack_size):
        local_name = pwndbg.integration.ida.GetMemberName(frame_id, i)
        if local_name != name:
            continue

        # Heuristic: Offset is relative to the base pointer or stack pointer
        # depending on if IDA is detecting a saved frame pointer or not.
        offset = pwndbg.integration.ida.GetMemberOffset(frame_id, local_name)
        if offset == -1:
            raise ValueError("ida.GetMemberOffset(%r) == -1" % local_name)
        if saved_baseptr != -1:
            return pwndbg.aglib.regs[pwndbg.aglib.regs.frame] + offset - saved_baseptr
        return pwndbg.aglib.regs[pwndbg.aglib.regs.stack] + offset
    return None


@GdbFunction()
def ida(name: gdb.Value) -> int:
    """
    Lookup a symbol's address by name from IDA.
    Evaluate ida.LocByName() on the supplied value.

    This functions doesn't see stack local variables.

    Example:
    ```
    pwndbg> set integration-provider ida
    Pwndbg successfully connected to Ida Pro xmlrpc: http://127.0.0.1:31337
    Set which provider to use for integration features to 'ida'.
    pwndbg> p main
    No symbol "main" in current context.
    pwndbg> p/x $ida("main")
    $1 = 0x555555555645
    pwndbg> b *$ida("main")
    Breakpoint 2 at 0x555555555645
    ```
    """
    name = name.string()

    # Lookup local variables first
    result = _ida_local(name)
    if result is not None:
        return result

    result = pwndbg.integration.ida.LocByName(name)
    if result is None:
        raise ValueError("ida.LocByName(%r) == None" % name)

    result_r = pwndbg.integration.ida.l2r(result)
    if 0xFFFFE000 <= result_r <= 0xFFFFFFFF or 0xFFFFFFFFFFFFE000 <= result_r <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("ida.LocByName(%r) == BADADDR" % name)

    return result
