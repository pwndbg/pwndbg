from __future__ import annotations

from pwndbg.aglib import arch as arch_mod
from pwndbg.aglib.arch import arch as arch

regs = None


def load_aglib():
    import pwndbg.aglib.argv
    import pwndbg.aglib.ctypes
    import pwndbg.aglib.disasm
    import pwndbg.aglib.disasm.aarch64
    import pwndbg.aglib.disasm.arm
    import pwndbg.aglib.disasm.mips
    import pwndbg.aglib.disasm.ppc
    import pwndbg.aglib.disasm.riscv
    import pwndbg.aglib.disasm.sparc
    import pwndbg.aglib.disasm.x86
    import pwndbg.aglib.dynamic
    import pwndbg.aglib.elf
    import pwndbg.aglib.file
    import pwndbg.aglib.heap
    import pwndbg.aglib.kernel
    import pwndbg.aglib.kernel.vmmap
    import pwndbg.aglib.memory
    import pwndbg.aglib.nearpc
    import pwndbg.aglib.next
    import pwndbg.aglib.onegadget
    import pwndbg.aglib.proc
    import pwndbg.aglib.qemu
    import pwndbg.aglib.regs as regs_mod
    import pwndbg.aglib.remote
    import pwndbg.aglib.stack
    import pwndbg.aglib.strings
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo
    import pwndbg.aglib.vmmap
    import pwndbg.aglib.vmmap_custom

    # This is necessary so that mypy understands the actual type of the regs module
    regs_: regs_mod.module = regs_mod
    global regs
    regs = regs_
