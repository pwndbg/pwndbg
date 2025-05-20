from __future__ import annotations

import argparse
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

import pwnlib.rop.srop

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.message
import pwndbg.commands
from pwndbg.commands import CommandCategory
from pwndbg.lib.regs import aarch64
from pwndbg.lib.regs import amd64
from pwndbg.lib.regs import arm
from pwndbg.lib.regs import i386

# Grab frame values from pwntools. Offsets are defined as the offset to stack pointer when syscall instruction is called
# Offsets and names are from Linux kernel source. For example x86_64 is defined in CONFIG_X86_64 struct rt_sigframe (Linux Kernel /arch/x86/include/asm/sigframe.h)
SIGRETURN_FRAME_LAYOUTS: Dict[str, List[Tuple[int, str]]] = {
    "x86-64": sorted([(-8, "&pretcode")] + list(pwnlib.rop.srop.registers["amd64"].items())),
    "i386": sorted(pwnlib.rop.srop.registers["i386"].items()),
    "aarch64": sorted(pwnlib.rop.srop.registers["aarch64"].items()),
    "arm": sorted(pwnlib.rop.srop.registers["arm"].items()),
}

# Always print these registers (as well as flag register, eflags / cpsr)
SIGRETURN_CORE_REGISTER: Dict[str, Set[str]] = {
    "x86-64": {*amd64.gpr, amd64.frame, amd64.stack, amd64.pc},
    "i386": {*i386.gpr, i386.frame, i386.stack, i386.pc},
    "aarch64": {*aarch64.gpr, "sp", "pc"},
    "arm": {*arm.gpr, "fp", "ip", "sp", "lr", "pc"},
}


parser = argparse.ArgumentParser(description="Display the SigreturnFrame at the specific address")

parser.add_argument(
    "address", nargs="?", default=None, type=int, help="The address to read the frame from"
)

parser.add_argument(
    "-a",
    "--all",
    dest="display_all",
    action="store_true",
    default=False,
    help="Show all values in the frame in addition to common registers",
)

parser.add_argument(
    "-p",
    "--print",
    dest="print_address",
    action="store_true",
    default=False,
    help="Show addresses of frame values",
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["x86-64", "i386", "aarch64", "arm"])
def sigreturn(address: int = None, display_all=False, print_address=False) -> None:
    address = pwndbg.aglib.regs.sp if address is None else address

    ptr_size = pwndbg.aglib.arch.ptrsize

    frame_layout = SIGRETURN_FRAME_LAYOUTS[pwndbg.aglib.arch.name]
    core_registers = SIGRETURN_CORE_REGISTER[pwndbg.aglib.arch.name]

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

        if reg in core_registers:
            desc = pwndbg.chain.format(value)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)

        elif reg in pwndbg.aglib.regs.flags:  # eflags or cpsr
            reg_flags = pwndbg.aglib.regs.flags[reg]
            desc = C.format_flags(value, reg_flags)

            print_value(f"{regname} {desc}", address + stack_offset, print_address)

        elif display_all:
            print_value(f"{reg} {M.get(value)}", address + stack_offset, print_address)


def print_value(string: str, address: int, print_address) -> None:
    addr = ""
    if print_address:
        addr = f"{M.get(address)}: "
    print(f"{addr}{string}")
