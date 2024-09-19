from __future__ import annotations

from typing import Tuple

import gdb

import pwndbg.commands
import pwndbg.gdblib.events
import pwndbg.gdblib.functions
import pwndbg.gdblib.regs
import pwndbg.integration.binja
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Synchronize Binary Ninja's cursor with GDB.",
    category=CommandCategory.INTEGRATIONS,
    command_name="bn-sync",
    aliases=["bns"],
)
@pwndbg.commands.OnlyWhenRunning
def bn_sync(*args) -> None:
    """
    Synchronize Binary Ninja's cursor with GDB
    """
    pwndbg.integration.binja.navigate_to(pwndbg.gdblib.regs.pc)


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_sym(name_val: gdb.Value) -> int | None:
    """Lookup a symbol's address by name from Binary Ninja."""
    name = name_val.string()
    addr: int | None = pwndbg.integration.binja._bn.get_symbol_addr(name)
    if addr is None:
        return None
    return pwndbg.integration.binja.r2l(addr)


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_var(name_val: gdb.Value) -> int | None:
    """Lookup a stack variable's address by name from Binary Ninja."""
    name = name_val.string()
    conf_and_offset: Tuple[int, int] | None = pwndbg.integration.binja._bn.get_var_offset_from_sp(
        pwndbg.integration.binja.l2r(pwndbg.gdblib.regs.pc), name
    )
    if conf_and_offset is None:
        return None
    (conf, offset) = conf_and_offset
    if conf < 64:
        print(message.warn(f"Warning: Stack offset only has {conf / 255 * 100:.2f}% confidence"))
    return pwndbg.gdblib.regs.sp + offset


@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.integration.binja.with_bn()
def bn_eval(expr: gdb.Value) -> int | None:
    """Parse and evaluate a Binary Ninja expression.

    Docs: https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView.parse_expression

    Adds all registers in the current register set as magic variables (e.g. $rip).
    Also adds a $piebase magic variable with the computed executable base.
    """
    magic_vars = {}
    for r in pwndbg.gdblib.regs.current:
        v = pwndbg.gdblib.regs[r]
        if v is not None:
            magic_vars[r] = v
    magic_vars["piebase"] = pwndbg.gdblib.proc.binary_base_addr
    ret: int | None = pwndbg.integration.binja._bn.parse_expr(expr.string(), magic_vars)
    return ret
