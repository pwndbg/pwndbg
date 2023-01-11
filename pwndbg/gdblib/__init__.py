# The `arch` module can be accessed with `from pwndbg.gdblib.arch import arch_mod`,
# while `pwndbg.gdblib.arch` will represent the `Arch` object

from pwndbg.gdblib import arch as arch_mod
from pwndbg.gdblib import config as config_mod
from pwndbg.gdblib.arch import arch
from pwndbg.gdblib.config import config

regs = None

__all__ = ["ctypes", "memory", "typeinfo"]


# TODO: should the imports above be moved here?
def load_gdblib() -> None:
    """
    Import all gdblib modules that need to run code on import
    """
    # pylint: disable=import-outside-toplevel
    import pwndbg.gdblib.abi
    import pwndbg.gdblib.android
    import pwndbg.gdblib.argv
    import pwndbg.gdblib.ctypes
    import pwndbg.gdblib.elf
    import pwndbg.gdblib.events
    import pwndbg.gdblib.functions
    import pwndbg.gdblib.hooks
    import pwndbg.gdblib.kernel
    import pwndbg.gdblib.memory
    import pwndbg.gdblib.prompt
    import pwndbg.gdblib.regs as regs_mod
    import pwndbg.gdblib.symbol
    import pwndbg.gdblib.typeinfo
    import pwndbg.gdblib.vmmap

    # This is necessary so that mypy understands the actual type of the regs module
    regs_: regs_mod.module = regs_mod
    global regs
    regs = regs_
