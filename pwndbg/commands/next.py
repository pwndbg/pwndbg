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
from pwndbg.lib.syscall import syscall_name_to_number
from pwndbg.lib.syscall import syscall_number_to_name


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


def _get_syscall_predicate(
    syscall_num: int | None, condition: Callable[[], int] | None
) -> Callable[[], bool] | None:
    """
    Helper function to build a predicate function for filtering syscalls based on syscall number and/or condition.
    """
    if syscall_num is not None:
        syscall_abi = pwndbg.aglib.arch.syscall_abi
        if syscall_abi is None:
            print("Cannot determine syscall ABI for current architecture")
            return None
        syscall_reg = syscall_abi.syscall_register

        def check_syscall() -> bool:
            return pwndbg.aglib.regs.read_reg(syscall_reg) == syscall_num

        if condition is not None:

            def check_syscall_and_condition() -> bool:
                return pwndbg.aglib.regs.read_reg(syscall_reg) == syscall_num and bool(condition())

            return check_syscall_and_condition
        return check_syscall
    if condition is not None:

        def check_condition() -> bool:
            try:
                return bool(condition())
            except Exception:
                return False

        return check_condition
    return None  # No filtering


async def _stepsyscall(
    ec: pwndbg.dbg_mod.ExecutionController,
    syscall_num: int | None = None,
    condition: Callable[[], int] | None = None,
) -> None:
    """
    Execution controller for the `stepsyscall` command.
    """
    # Build predicate once based on what filters are provided
    predicate: Callable[[], bool] | None = _get_syscall_predicate(syscall_num, condition)

    if predicate is None:
        while (
            pwndbg.aglib.proc.alive()
            and not (await pwndbg.aglib.next.break_next_interrupt(ec, honor_current_branch=True))
            and (await pwndbg.aglib.next.break_next_branch(ec, including_current=True))
        ):
            # Here we are e.g. on a CALL instruction (temporarily breakpointed by `break_next_branch`)
            # We need to step so that we take this branch instead of ignoring it
            await ec.single_step()
            continue
    else:
        while (
            pwndbg.aglib.proc.alive()
            and not (
                await pwndbg.aglib.next.break_next_interrupt_filtered(
                    ec, predicate=predicate, honor_current_branch=True
                )
            )
            and (await pwndbg.aglib.next.break_next_branch(ec, including_current=True))
        ):
            await ec.single_step()
            continue


stepsyscall_parser = argparse.ArgumentParser(
    description="Breaks at the next syscall by taking branches."
)
stepsyscall_parser.add_argument(
    "syscall",
    type=str,
    nargs="?",
    default=None,
    help="Syscall number (e.g., 1, 0x3c) or name (e.g., write, exit)",
)
stepsyscall_parser.add_argument(
    "-c",
    "--condition",
    type=str,
    default=None,
    help="Condition to match (e.g., '$rdi==0', '$rsi>100')",
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
        stepsyscall                    - Break at next syscall
        stepsyscall write              - Break at next write syscall
        stepsyscall 1                  - Break at syscall number 1
        stepsyscall write -c '$rdi==1' - Break at write syscall when fd==1 (stdout)
        stepsyscall -c '$rax==60'      - Break when syscall number is 60 (exit)
    """
    syscall_num = None
    cond_callable = None

    # Parse syscall argument
    if syscall is not None:
        arch_name = pwndbg.aglib.arch.name
        if not arch_name:
            print("Cannot determine architecture")
            return

        # Try parsing as number first
        try:
            num = int(syscall, 0)  # base 0 auto-detects hex/octal
            name = syscall_number_to_name(num, arch_name)
            if name is None:
                print(f"Unknown syscall number: {syscall}")
                return
            syscall_num = num
        except ValueError:
            # Not a number, try as name
            num = syscall_name_to_number(syscall, arch_name)
            if num is None:
                print(f"Unknown syscall: {syscall}")
                return
            syscall_num = num

    # Parse condition argument
    if condition is not None:
        cond_str = condition
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
