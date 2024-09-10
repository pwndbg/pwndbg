# The `arch` module can be accessed with `from pwndbg.gdblib.arch import arch_mod`,
# while `pwndbg.gdblib.arch` will represent the `Arch` object

from __future__ import annotations

import re
from types import ModuleType

import gdb

from pwndbg.gdblib import arch as arch_mod
from pwndbg.gdblib import config as config_mod
from pwndbg.gdblib.arch import arch as arch

regs = None

__all__ = ["ctypes", "memory", "typeinfo"]

# Export parsed GDB version
gdb_version = tuple(map(int, re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()))


# TODO: should the imports above be moved here?
def load_gdblib() -> None:
    """
    Import all gdblib modules that need to run code on import
    """
    # pylint: disable=import-outside-toplevel
    import pwndbg.gdblib.abi
    import pwndbg.gdblib.android
    import pwndbg.gdblib.argv
    import pwndbg.gdblib.bpoint
    import pwndbg.gdblib.ctypes
    import pwndbg.gdblib.elf
    import pwndbg.gdblib.functions
    import pwndbg.gdblib.got
    import pwndbg.gdblib.hooks
    import pwndbg.gdblib.kernel
    import pwndbg.gdblib.memory
    import pwndbg.gdblib.onegadget
    import pwndbg.gdblib.prompt
    import pwndbg.gdblib.regs as regs_mod
    import pwndbg.gdblib.symbol
    import pwndbg.gdblib.tui
    import pwndbg.gdblib.typeinfo
    import pwndbg.gdblib.vmmap

    # This is necessary so that mypy understands the actual type of the regs module
    regs_: regs_mod.module = regs_mod
    global regs
    regs = regs_
