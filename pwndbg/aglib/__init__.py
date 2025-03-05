from __future__ import annotations

from pwndbg.aglib import arch as arch_mod
# from pwndbg.aglib.arch import arch as arch

from pwndbg.aglib.arch import PwndbgArchitecture

regs = None

# arch: PwndbgArchitecture = None
arch: PwndbgArchitecture = PwndbgArchitecture.get_arch("i386")

def load_aglib():
    import pwndbg.aglib.argv
    import pwndbg.aglib.ctypes
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

def set_arch(pwndbg_arch: PwndbgArchitecture):
    global arch
    arch = pwndbg_arch