from __future__ import annotations

import re
from types import ModuleType

import gdb

from pwndbg.gdblib import config as config_mod

regs = None

__all__ = ()

# Export parsed GDB version
gdb_version = tuple(map(int, re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()))


# TODO: should the imports above be moved here?
def load_gdblib() -> None:
    """
    Import all gdblib modules that need to run code on import
    """
    # pylint: disable=import-outside-toplevel
    import pwndbg.gdblib.abi
    import pwndbg.gdblib.argv
    import pwndbg.gdblib.bpoint
    import pwndbg.gdblib.functions
    import pwndbg.gdblib.got
    import pwndbg.gdblib.hooks
    import pwndbg.gdblib.prompt
    import pwndbg.gdblib.symbol
    import pwndbg.gdblib.tui
