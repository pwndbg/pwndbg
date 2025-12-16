"""
Debugger-agnostic library that provides various functionality.

Takes the debugging primitives provided by the Debugger API
and builds the more complex and interesting bits of functionality
found in Pwndbg on top of them.

See https://pwndbg.re/dev/contributing/dev-notes/#aglib
for more information.
"""

from __future__ import annotations

from typing import cast

from pwndbg.aglib.arch_mod import PwndbgArchitecture
from pwndbg.aglib.regs_mod import RegisterManager

# These will be set during debugger setup.
# Thus you can't import them with `from pwndbg.aglib import arch`.
arch: PwndbgArchitecture = cast(PwndbgArchitecture, None)
regs: RegisterManager = cast(RegisterManager, None)


def load_aglib():
    import pwndbg.aglib.argv
    import pwndbg.aglib.ctypes
    import pwndbg.aglib.dynamic
    import pwndbg.aglib.elf
    import pwndbg.aglib.file
    import pwndbg.aglib.heap
    import pwndbg.aglib.kernel
    import pwndbg.aglib.kernel.vmmap
    import pwndbg.aglib.macho
    import pwndbg.aglib.memory
    import pwndbg.aglib.nearpc
    import pwndbg.aglib.next
    import pwndbg.aglib.objc
    import pwndbg.aglib.onegadget
    import pwndbg.aglib.proc
    import pwndbg.aglib.qemu
    import pwndbg.aglib.regs_mod
    import pwndbg.aglib.remote
    import pwndbg.aglib.stack
    import pwndbg.aglib.strings
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo
    import pwndbg.aglib.vmmap
    import pwndbg.aglib.vmmap_custom

    global regs
    regs = pwndbg.aglib.regs_mod.regs


def set_arch(pwndbg_arch: PwndbgArchitecture):
    global arch
    arch = pwndbg_arch
