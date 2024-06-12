from __future__ import annotations

import argparse

import gdb
from capstone import CS_GRP_JUMP

import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.gdblib.bpoint
import pwndbg.gdblib.disasm
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.next
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction


class BreakOnConditionalBranch(pwndbg.gdblib.bpoint.Breakpoint):
    """
    A breakpoint that only stops the inferior if a given branch is taken or not taken.
    """

    def __init__(self, instruction: PwndbgInstruction, taken: bool) -> None:
        super().__init__("*%#x" % instruction.address, type=gdb.BP_BREAKPOINT, internal=False)
        self.instruction = instruction
        self.taken = taken

    def should_stop(self):
        # Use the assistant to figure out which if all the conditions this
        # branch requires in order to be taken have been met.
        assistant = pwndbg.gdblib.disasm.arch.DisassemblyAssistant.for_current_arch()
        assistant.enhance(self.instruction)
        condition_met = self.instruction.is_conditional_jump_taken

        return condition_met == self.taken


parser = argparse.ArgumentParser(description="Breaks on a branch if it is taken.")
parser.add_argument(
    "branch",
    type=str,
    help="The branch instruction to break on.",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="break-if-taken")
@pwndbg.commands.OnlyWhenRunning
def break_if_taken(branch) -> None:
    install_breakpoint(branch, taken=True)


parser = argparse.ArgumentParser(description="Breaks on a branch if it is not taken.")
parser.add_argument(
    "branch",
    type=str,
    help="The branch instruction to break on.",
)


@pwndbg.commands.ArgparsedCommand(parser, command_name="break-if-not-taken")
@pwndbg.commands.OnlyWhenRunning
def break_if_not_taken(branch) -> None:
    install_breakpoint(branch, taken=False)


def install_breakpoint(branch, taken: bool) -> None:
    # Do our best to interpret branch as an address locspec. Untimately, though,
    # we're limited in what we can do from inside Python in that front.
    #
    # https://sourceware.org/gdb/onlinedocs/gdb/Address-Locations.html#Address-Locations
    address = None
    try:
        # Try to interpret branch as an address literal
        address = int(branch, 0)
    except ValueError:
        # That didn't work. Defer to GDB and see if it can make something out of
        # the address value we were given.
        try:
            value = gdb.parse_and_eval(branch)
            if value.address is None:
                print(message.warn(f"Value {branch} has no address, trying its value"))
                address = int(value)
            else:
                address = int(value.address)
        except gdb.error as e:
            # No such luck. Report to the user and quit.
            print(message.error(f"Could not resolve branch location {branch}: {e}"))
            return

    # We should've picked something by now, or errored out.
    instruction = pwndbg.gdblib.disasm.one(address)
    if instruction is None:
        print(message.error(f"Could not decode instruction at address {address:#x}"))
        return
    if CS_GRP_JUMP not in instruction.groups:
        print(
            message.error(
                f"Instruction '{instruction.mnemonic} {instruction.op_str}' at address {address:#x} is not a branch"
            )
        )
        return

    # Not all architectures have assistants we can use for conditionals.
    if pwndbg.gdblib.disasm.arch.DisassemblyAssistant.for_current_arch() is None:
        print(
            message.error(
                "The current architecture is not supported for breaking on conditional branches"
            )
        )
        return

    # Install the breakpoint.
    BreakOnConditionalBranch(instruction, taken)
