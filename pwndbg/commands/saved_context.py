from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.color.message
import pwndbg.commands
from pwndbg.aglib.saved_context import ARM_CORTEX_M_EXCEPTION_STACK
from pwndbg.aglib.saved_context import SavedContext
from pwndbg.commands.sigreturn import print_value


def print_saved_context(context: SavedContext, address: int = None, print_address=False):
    address = pwndbg.aglib.regs.sp if address is None else address

    ptr_size = pwndbg.aglib.arch.ptrsize

    frame_layout = context.frame_layout

    # Offset to the stack pointer where the frame values really begins. Start reading memory there.
    # Can be negative, 0, or positive
    frame_start_offset = frame_layout[0][0]

    read_size = frame_layout[-1][0] - frame_start_offset + ptr_size

    mem = pwndbg.aglib.memory.read(address + frame_start_offset, read_size)

    for stack_offset, reg in frame_layout:
        # Subtract the offset of start of frame, to get the correct offset into "mem"
        mem_offset = stack_offset - frame_start_offset

        regname = C.register(reg.ljust(4).upper())
        value = pwndbg.aglib.arch.unpack(mem[mem_offset : mem_offset + ptr_size])

        if reg in pwndbg.aglib.regs.flags:  # eflags or cpsr
            reg_flags = pwndbg.aglib.regs.flags[reg]
            desc = C.format_flags(value, reg_flags)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)
        else:
            desc = pwndbg.chain.format(value)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)


def create_saved_context_printer(
    command_name: str, desc: str, context: SavedContext, arches: list[str]
):
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        "address", nargs="?", default=None, type=int, help="The address to read the frame from"
    )

    parser.add_argument(
        "-p",
        "--print",
        dest="print_address",
        action="store_true",
        default=False,
        help="Show addresses of frame values",
    )

    @pwndbg.commands.ArgparsedCommand(parser, command_name=command_name)
    @pwndbg.commands.OnlyWhenRunning
    @pwndbg.aglib.proc.OnlyWithArch(arches)
    def saved_context(address: int = None, print_address=False) -> None:
        print_saved_context(context, address, print_address)


create_saved_context_printer(
    "saved_arm_exception_context",
    "Display the state saved for an Arm-M exception at the specific address",
    ARM_CORTEX_M_EXCEPTION_STACK,
    arches=["armcm"],
)
