from __future__ import annotations

import argparse
import collections

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.message
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.lib.regs import amd64 as amd64_regset

parser = argparse.ArgumentParser(description="Display the SigreturnFrame at the specific address")

parser.add_argument(
    "address", nargs="?", default=None, type=int, help="The address to read the frame"
)

parser.add_argument(
    "-a",
    "--all",
    dest="display_all",
    action="store_true",
    default=False,
    help="Show all values in the frame in addition to registers",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithArch(["x86-64"])
def sigreturn(address: int = None, display_all=False):
    address = pwndbg.gdblib.regs.sp if address is None else address

    arch_name = pwndbg.gdblib.arch.name
    if arch_name == "x86-64":
        sigreturn_x86_64(address, display_all)
    else:
        print(
            pwndbg.color.message.error(f"sigreturn does not support the {arch_name} architecture")
        )


SIGRETURN_FRAME_SIZE_x86_64 = 256

# Original registers layout from pwntools, modified below : https://github.com/Gallopsled/pwntools/blob/e4d3c82501c03de44458ae498a830fe66594f66d/pwnlib/rop/srop.py#L256
# Offsets and names from "CONFIG_X86_64 struct rt_sigframe, Linux Kernel /arch/x86/include/asm/sigframe.h
SIGRETURN_FRAME_LAYOUT_x86_64 = collections.OrderedDict(
    [
        ("&pretcode", 0),
        ("uc_flags", 8),
        ("&uc", 16),
        ("uc_stack.ss_sp", 24),
        ("uc_stack.ss_flags", 32),
        ("uc_stack.ss_size", 40),
        ("r8", 48),
        ("r9", 56),
        ("r10", 64),
        ("r11", 72),
        ("r12", 80),
        ("r13", 88),
        ("r14", 96),
        ("r15", 104),
        ("rdi", 112),
        ("rsi", 120),
        ("rbp", 128),
        ("rbx", 136),
        ("rdx", 144),
        ("rax", 152),
        ("rcx", 160),
        ("rsp", 168),
        ("rip", 176),
        ("eflags", 184),
        ("csgsfs", 192),
        ("err", 200),
        ("trapno", 208),
        ("oldmask", 216),
        ("cr2", 224),
        ("&fpstate", 232),
        ("__reserved", 240),
        ("sigmask", 248),
    ]
)

# Core registers
SIGRETURN_REGISTERS_x86_64 = set(
    [*amd64_regset.gpr, amd64_regset.frame, amd64_regset.stack, amd64_regset.pc]
)


def sigreturn_x86_64(address: int, display_all: bool):
    ptr_size = 8  # x86_64

    # Offset by -8, where the frame begins (in relation to stack pointer)
    mem = pwndbg.gdblib.memory.read(address - 8, SIGRETURN_FRAME_SIZE_x86_64)

    # The pointer before stack pointer is address of signal trampoline
    # Display registers
    for reg, offset in SIGRETURN_FRAME_LAYOUT_x86_64.items():
        if reg in SIGRETURN_REGISTERS_x86_64:
            regname = C.register(reg.ljust(4).upper())
            value = pwndbg.gdblib.arch.unpack(mem[offset : offset + ptr_size])
            desc = pwndbg.chain.format(value)

            print(f"{regname} {desc}")

        elif reg == "eflags":
            regname = C.register("eflags".ljust(4).upper())
            value = pwndbg.gdblib.arch.unpack(mem[offset : offset + ptr_size])
            reg_flags = pwndbg.gdblib.regs.flags["eflags"]
            desc = C.format_flags(value, reg_flags)

            print(f"{regname} {desc}")

        elif display_all:
            desc = pwndbg.gdblib.arch.unpack(mem[offset : offset + ptr_size])

            print(f"{reg} {M.get(desc)}")
