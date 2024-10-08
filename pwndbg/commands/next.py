"""
Stepping until an event occurs
"""

from __future__ import annotations

import argparse

import pwndbg.aglib.next
import pwndbg.commands
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Breaks at the next jump instruction.", aliases=["nextjump"], category=CommandCategory.NEXT
)
@pwndbg.commands.OnlyWhenRunning
def nextjmp() -> None:
    """Breaks at the next jump instruction"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        await pwndbg.aglib.next.break_next_branch(ec)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


parser = argparse.ArgumentParser(description="Breaks at the next call instruction.")
parser.add_argument(
    "symbol_regex",
    type=str,
    default=None,
    nargs="?",
    help="A regex matching the name of next symbol to be broken on before calling.",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def nextcall(symbol_regex=None) -> None:
    """Breaks at the next call instruction"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        if await pwndbg.aglib.next.break_next_call(ec, symbol_regex):
            pwndbg.commands.context.context()

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


@pwndbg.commands.ArgparsedCommand(
    "Breaks at next return-like instruction.", category=CommandCategory.NEXT
)
@pwndbg.commands.OnlyWhenRunning
def nextret() -> None:
    """Breaks at next return-like instruction"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        if await pwndbg.aglib.next.break_next_ret(ec):
            pwndbg.commands.context.context()

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


@pwndbg.commands.ArgparsedCommand(
    "Breaks at next return-like instruction by 'stepping' to it.", category=CommandCategory.NEXT
)
@pwndbg.commands.OnlyWhenRunning
def stepret() -> None:
    """Breaks at next return-like instruction by 'stepping' to it"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        while (
            pwndbg.aglib.proc.alive
            and not (await pwndbg.aglib.next.break_next_ret(ec))
            and (await pwndbg.aglib.next.break_next_branch(ec))
        ):
            # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
            # We need to step so that we take this branch instead of ignoring it
            await ec.single_step()
            continue

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


@pwndbg.commands.ArgparsedCommand(
    "Breaks at the next instruction that belongs to the running program.",
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def nextproginstr() -> None:
    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        await pwndbg.aglib.next.break_on_program_code(ec)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


parser = argparse.ArgumentParser(description="Breaks on the instruction after this one.")
parser.add_argument("addr", type=int, default=None, nargs="?", help="The address to break after.")


@pwndbg.commands.ArgparsedCommand(parser, aliases=["so"], category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def stepover(addr=None) -> None:
    """Sets a breakpoint on the instruction after this one"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        await pwndbg.aglib.next.break_on_next(ec, addr)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


@pwndbg.commands.ArgparsedCommand(
    "Breaks at the next syscall not taking branches.",
    aliases=["nextsc"],
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def nextsyscall() -> None:
    """
    Breaks at the next syscall not taking branches.
    """

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        while (
            pwndbg.aglib.proc.alive
            and not (await pwndbg.aglib.next.break_next_interrupt(ec))
            and (await pwndbg.aglib.next.break_next_branch(ec))
        ):
            continue

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


@pwndbg.commands.ArgparsedCommand(
    "Breaks at the next syscall by taking branches.",
    aliases=["stepsc"],
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def stepsyscall() -> None:
    """
    Breaks at the next syscall by taking branches.
    """

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        while (
            pwndbg.aglib.proc.alive
            and not (await pwndbg.aglib.next.break_next_interrupt(ec))
            and (await pwndbg.aglib.next.break_next_branch(ec))
        ):
            # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
            # We need to step so that we take this branch instead of ignoring it
            await ec.single_step()
            continue

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


parser = argparse.ArgumentParser(description="Breaks on the next matching instruction.")
parser.add_argument("mnemonic", type=str, help="The mnemonic of the instruction")
parser.add_argument(
    "op_str",
    type=str,
    nargs="*",
    help="The operands of the instruction",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def stepuntilasm(mnemonic, op_str) -> None:
    if len(op_str) == 0:
        op_str = None

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        await pwndbg.aglib.next.break_on_next_matching_instruction(ec, mnemonic, op_str)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
