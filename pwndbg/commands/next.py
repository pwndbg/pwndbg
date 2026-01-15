"""
Stepping until an event occurs
"""

from __future__ import annotations

import argparse
from collections.abc import Callable

import pwndbg.aglib.next
import pwndbg.aglib.proc
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.dbg_mod
from pwndbg.commands import CommandCategory
from pwndbg.lib.syscall import get_syscall


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


async def _stepsyscall(
    ec: pwndbg.dbg_mod.ExecutionController,
    syscall_num: int | None = None,
    condition: Callable[[], int] | None = None,
) -> None:
    """
    Execution controller for the `stepsyscall` command.
    """

    def predicate() -> bool:
        # If syscall filter is provided, check current syscall number
        if syscall_num is not None:
            syscall_abi = pwndbg.aglib.arch.syscall_abi
            if syscall_abi is None:
                return False
            syscall_reg = syscall_abi.syscall_register
            current_syscall = pwndbg.aglib.regs.read_reg(syscall_reg)
            if current_syscall != syscall_num:
                return False
        # If condition is provided, evaluate it
        if condition is not None:
            try:
                if not condition():
                    return False
            except Exception:
                return False
        return True

    if await pwndbg.aglib.next.break_next_interrupt_filtered(ec, predicate=predicate):
        pwndbg.commands.context.context()


stepsyscall_parser = argparse.ArgumentParser(
    description="Breaks at the next syscall by taking branches."
)
stepsyscall_parser.add_argument(
    "syscall",
    type=str,
    nargs="?",
    default=None,
    help="Syscall number (e.g., 1, 0x3c) or name (e.g., SYS_write, SYS_exit)",
)
stepsyscall_parser.add_argument(
    "condition",
    type=str,
    nargs="?",
    default=None,
    help="Condition to match (e.g., $rdi==0, $rsi>100)",
)


@pwndbg.commands.Command(
    stepsyscall_parser,
    aliases=["stepsc"],
    category=CommandCategory.NEXT,
)
@pwndbg.commands.OnlyWhenRunning
def stepsyscall(syscall: str | None = None, condition: str | None = None) -> None:
    """
    Breaks at the next syscall by taking branches.

    Examples:
        stepsyscall                  - Break at next syscall
        stepsyscall SYS_write        - Break at next write syscall
        stepsyscall 1                - Break at syscall number 1
        stepsyscall SYS_write $rdi==1  - Break at write syscall when fd==1 (stdout)
        stepsyscall $rax==60         - Break when syscall number is 60 (exit)
    """
    syscall_num = None
    cond_callable = None

    # Parse syscall argument
    if syscall is not None:
        # Check if it's a condition (starts with $ or contains operators)
        if syscall.startswith("$") or any(op in syscall for op in ["==", "!=", ">", "<"]):
            # It's a condition, not a syscall name/number
            cond_str = syscall
            cond_callable = lambda cond=cond_str: int(
                pwndbg.dbg.selected_inferior().evaluate_expression(cond)
            )
        else:
            arch_name = pwndbg.aglib.arch.name if pwndbg.aglib.arch else None
            num, name = get_syscall(syscall, arch_name)
            if num is None:
                print(f"Unknown syscall: {syscall}")
                return
            syscall_num = num
            print(f"Stepping until syscall {name} ({num})")

    # Parse condition argument (can be combined with syscall filter)
    if condition is not None:
        cond_str = condition
        # If we already have a condition from syscall arg, we need to combine them
        cond_callable = lambda cond=cond_str: int(
            pwndbg.dbg.selected_inferior().evaluate_expression(cond)
        )

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController) -> None:
        await _stepsyscall(ec, syscall_num=syscall_num, condition=cond_callable)

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)


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
