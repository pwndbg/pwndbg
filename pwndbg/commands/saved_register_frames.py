from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.memory
import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.commands
from pwndbg.aglib.saved_register_frames import ARM_CORTEX_M_EXCEPTION_STACK
from pwndbg.aglib.saved_register_frames import SavedRegisterFrame
from pwndbg.commands import CommandCategory
from pwndbg.commands.sigreturn import print_value


def print_saved_register_frame(
    context: SavedRegisterFrame, address: int = None, print_address=False
):
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
        else:
            desc = pwndbg.chain.format(value)

        print_value(f"{regname} {desc}", address + stack_offset, print_address)


VALID_FRAME_TYPES = {
    "armcm-exception": ARM_CORTEX_M_EXCEPTION_STACK,
    "armcm-exception2": ARM_CORTEX_M_EXCEPTION_STACK,
}

parser = argparse.ArgumentParser(
    description="Display the registers saved to memory for a certain frame type"
)

parser.add_argument(
    "frame_type", choices=tuple(VALID_FRAME_TYPES), type=str, help="The type of frame to print"
)

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


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def dump_register_frame(frame_type: str, address: int = None, print_address=False) -> None:
    register_frame = VALID_FRAME_TYPES.get(frame_type)
    if register_frame is None:
        print(f"Invalid frame type: {frame_type} (valid: {','.join(VALID_FRAME_TYPES.keys())})")
        return

    print_saved_register_frame(register_frame, address, print_address)
