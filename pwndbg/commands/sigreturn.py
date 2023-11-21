from __future__ import annotations

import argparse

import pwndbg.color.context as C
import pwndbg.color.message
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs

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


SIGRETURN_FRAME_SIZE_x86_64 = 248

# Registers layout from pwntools: https://github.com/Gallopsled/pwntools/blob/e4d3c82501c03de44458ae498a830fe66594f66d/pwnlib/rop/srop.py#L256
SIGRETURN_FRAME_LAYOUT_x86_64 = {
    "uc_flags": 0,
    "&uc": 8,
    "uc_stack.ss_sp": 16,
    "uc_stack.ss_flags": 24,
    "uc_stack.ss_size": 32,
    "r8": 40,
    "r9": 48,
    "r10": 56,
    "r11": 64,
    "r12": 72,
    "r13": 80,
    "r14": 88,
    "r15": 96,
    "rdi": 104,
    "rsi": 112,
    "rbp": 120,
    "rbx": 128,
    "rdx": 136,
    "rax": 144,
    "rcx": 152,
    "rsp": 160,
    "rip": 168,
    "eflags": 176,
    "csgsfs": 184,
    "err": 192,
    "trapno": 200,
    "oldmask": 208,
    "cr2": 216,
    "&fpstate": 224,
    "__reserved": 232,
    "sigmask": 240,
}

SIGRETURN_REGISTERS_x86_64 = [
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rdi",
    "rsi",
    "rbp",
    "rbx",
    "rdx",
    "rax",
    "rcx",
    "rsp",
    "rip",
]


def sigreturn_x86_64(address: int, display_all: bool):
    # TODO: make print output a lot nicer (similar to regs, with all the colors)
    # TODO: do a validation check to ensure the frame is valid
    # https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf
    # page 8 - code segment register should be 0x33
    #  fpstate points to the saved floating point state, or NULL

    # x86_64
    ptr_size = 8

    # Display registers
    mem = pwndbg.gdblib.memory.read(address, SIGRETURN_FRAME_SIZE_x86_64)

    for reg in SIGRETURN_REGISTERS_x86_64:
        offset = SIGRETURN_FRAME_LAYOUT_x86_64[reg]
        regname = C.register(reg.ljust(4).upper())

        value = pwndbg.gdblib.arch.unpack(mem[offset : offset + ptr_size])
        desc = pwndbg.chain.format(value)

        print(f"{regname} {desc}")

    # Display eflags
    regname = C.register("eflags".ljust(4).upper())
    eflags_offset = SIGRETURN_FRAME_LAYOUT_x86_64["eflags"]
    value = pwndbg.gdblib.arch.unpack(mem[eflags_offset : eflags_offset + ptr_size])
    reg_flags = pwndbg.gdblib.regs.flags["eflags"]

    desc = C.format_flags(value, reg_flags)

    print(f"{regname} {desc}")
