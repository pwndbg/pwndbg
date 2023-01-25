import argparse

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs

parser = argparse.ArgumentParser(description="")


@pwndbg.commands.ArgparsedCommand(parser)
def sigreturn():
    mem = pwndbg.gdblib.memory.read(pwndbg.gdblib.regs.rsp, 0x400)
    for i, reg in enumerate(
        [
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
            "eflags",
        ]
    ):
        offset = 0x28 + i * 8
        print(reg, hex(pwndbg.gdblib.arch.unpack((mem[offset : offset + 8]))))
