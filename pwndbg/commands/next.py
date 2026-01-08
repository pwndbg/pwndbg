"""
Stepping until an event occurs
"""

from __future__ import annotations

import argparse

import pwndbg.aglib.next
import pwndbg.aglib.proc
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.dbg_mod
from pwnlib.constants import linux
from pwndbg.commands import CommandCategory


async def _nextjmp(ec: pwndbg.dbg_mod.ExecutionController):
    """
    Execution controller for the `nextjmp` command.
    """

    if await pwndbg.aglib.next.break_next_branch(ec):
        pwndbg.commands.context.context()


@pwndbg.commands.Command(
    "Breaks at the next jump instruction.", aliases=["nextjump"], category=CommandCategory.NEXT
)
@pwndbg.commands.OnlyWhenRunning
def nextjmp() -> None:
    """Breaks at the next jump instruction"""

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_nextjmp)


parser = argparse.ArgumentParser(description="Breaks at the next call instruction.")
parser.add_argument(
    "symbol_regex",
    type=str,
    default=None,
    nargs="?",
    help="A regex matching the name of next symbol to be broken on before calling.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def nextcall(symbol_regex=None) -> None:
    """Breaks at the next call instruction"""

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        if await pwndbg.aglib.next.break_next_call(ec, symbol_regex):
            pwndbg.commands.context.context()

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


async def _nextret(ec: pwndbg.dbg_mod.ExecutionController):
    """
    Execution controller for the `nextret` command.
    """
    if await pwndbg.aglib.next.break_next_ret(ec):
        pwndbg.commands.context.context()


@pwndbg.commands.Command("Breaks at next return-like instruction.", category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def nextret() -> None:
    """Breaks at next return-like instruction"""

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_nextret)


async def _stepret(ec: pwndbg.dbg_mod.ExecutionController):
    """
    Execution controller for the `stepret` command.
    """
    while (
        pwndbg.aglib.proc.alive()
        and not (await pwndbg.aglib.next.break_next_ret(ec))
        and (await pwndbg.aglib.next.break_next_branch(ec))
    ):
        # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
        # We need to step so that we take this branch instead of ignoring it
        await ec.single_step()
        continue


@pwndbg.commands.Command(
    "Breaks at next return-like instruction by 'stepping' to it.", category=CommandCategory.NEXT
)
@pwndbg.commands.OnlyWhenRunning
def stepret() -> None:
    """Breaks at next return-like instruction by 'stepping' to it"""

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_stepret)


async def _nextproginstr(ec: pwndbg.dbg_mod.ExecutionController):
    """
    Execution controller for the `nextproginstr` command.
    """
    await pwndbg.aglib.next.break_on_program_code(ec)


@pwndbg.commands.Command(
    "Breaks at the next instruction that belongs to the running program.",
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def nextproginstr() -> None:
    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_nextproginstr)


parser = argparse.ArgumentParser(description="Breaks on the instruction after this one.")
parser.add_argument("addr", type=int, default=None, nargs="?", help="The address to break after.")


@pwndbg.commands.Command(parser, aliases=["so"], category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def stepover(addr=None) -> None:
    """Sets a breakpoint on the instruction after this one"""

    async def _stepover(ec: pwndbg.dbg_mod.ExecutionController):
        """
        Execution controller for the `stepover` command.
        """
        await pwndbg.aglib.next.break_on_next(ec, addr)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_stepover)


async def _nextsyscall(ec: pwndbg.dbg_mod.ExecutionController):
    """
    Execution controller for the `nextsyscall` command
    """
    while (
        pwndbg.aglib.proc.alive()
        and not (await pwndbg.aglib.next.break_next_interrupt(ec))
        and (await pwndbg.aglib.next.break_next_branch(ec))
    ):
        continue


@pwndbg.commands.Command(
    "Breaks at the next syscall not taking branches.",
    aliases=["nextsc"],
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def nextsyscall() -> None:
    """
    Breaks at the next syscall not taking branches.
    """
    pwndbg.dbg.selected_inferior().dispatch_execution_controller(_nextsyscall)


async def _stepsyscall(ec: pwndbg.dbg_mod.ExecutionController, argument: str | None = None):
    """
    Execution controller for the `stepsyscall` command.
    """
    target_syscall_nr = None
    remaining_condition = None

    if argument:
        words = argument.split()
        first_word = words[0]

        # 1. Try to resolve as syscall number
        try:
            target_syscall_nr = int(first_word, 0)
            remaining_condition = " ".join(words[1:]) if len(words) > 1 else None
        except ValueError:
            # 2. Try to resolve as syscall name
            arch_name = pwndbg.aglib.arch.name
            arch_module = {
                "arm": linux.arm,
                "armcm": linux.arm,
                "i386": linux.i386,
                "mips": linux.mips,
                "x86-64": linux.amd64,
                "aarch64": linux.aarch64,
                "rv32": linux.riscv64,
                "rv64": linux.riscv64,
            }.get(arch_name)

            if arch_module:
                name = first_word.lower()
                if name.startswith("sys_"):
                    name = name[4:]

                # In pwnlib, constants are usually prefixed with __NR_
                nr = getattr(arch_module, "__NR_" + name, None)
                if nr is not None:
                    target_syscall_nr = nr
                    remaining_condition = " ".join(words[1:]) if len(words) > 1 else None
                else:
                    # Treat the whole thing as an expression
                    remaining_condition = argument
            else:
                # Fallback to expression for unknown arches
                remaining_condition = argument

    while pwndbg.aglib.proc.alive():
        # Stop at the next syscall in the block
        ins = await pwndbg.aglib.next.break_next_interrupt(ec, honor_current_branch=True)
        if ins:
            # We are now at the syscall. Re-fetch the instruction to get register enhancement!
            ins = pwndbg.aglib.disasm.disassembly.one(pwndbg.aglib.regs.pc)
            if not ins:
                # Should not happen
                return

            # Check criteria
            match = True
            if target_syscall_nr is not None:
                if ins.syscall != target_syscall_nr:
                    match = False

            if match and remaining_condition:
                try:
                    val = pwndbg.dbg.selected_inferior().evaluate_expression(remaining_condition)
                    if not val:
                        match = False
                except pwndbg.dbg_mod.Error:
                    # On error, we stop and let the user see what happened
                    return

            if match:
                # We found the syscall we were looking for
                return

            # Not a match, nudge forward so we don't hit the same syscall again
            await ec.single_step()
            continue

        # No syscall in current block, move to next block
        if await pwndbg.aglib.next.break_next_branch(ec, including_current=True):
            await ec.single_step()
            continue
        break


parser = argparse.ArgumentParser(description="Breaks at the next syscall by taking branches.")
parser.add_argument(
    "argument",
    type=str,
    nargs="*",
    default=None,
    help="Syscall name, number, or expression to stop at.",
)


@pwndbg.commands.Command(parser, aliases=["stepsc"], category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def stepsyscall(argument=None) -> None:
    """
    Breaks at the next syscall by taking branches.
    """
    # Join multiple arguments into a single string
    full_argument = " ".join(argument) if argument else None

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(
        lambda ec: _stepsyscall(ec, full_argument)
    )


parser = argparse.ArgumentParser(description="Breaks on the next matching instruction.")
parser.add_argument("mnemonic", type=str, help="The mnemonic of the instruction")
parser.add_argument(
    "op_str",
    type=str,
    nargs="*",
    help="The operands of the instruction",
)


@pwndbg.commands.Command(parser, category=CommandCategory.NEXT)
@pwndbg.commands.OnlyWhenRunning
def stepuntilasm(mnemonic, op_str) -> None:
    if len(op_str) == 0:
        op_str = None

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        await pwndbg.aglib.next.break_on_next_matching_instruction(ec, mnemonic, op_str)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
