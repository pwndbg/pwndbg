# The `arch` module can be accessed with `from pwndbg.gdblib.arch import arch_mod`,
# while `pwndbg.gdblib.arch` will represent the `Arch` object
from pwndbg.gdblib import arch as arch_mod
from pwndbg.gdblib.arch import arch

__all__ = ["ctypes", "memory", "typeinfo"]


# TODO: should the imports above be moved here?
def load_gdblib():
    import pwndbg.gdblib.android
    import pwndbg.gdblib.arch
    import pwndbg.gdblib.argv
    import pwndbg.gdblib.ctypes
    import pwndbg.gdblib.dt
    import pwndbg.gdblib.events
    import pwndbg.gdblib.hooks
    import pwndbg.gdblib.memory
    import pwndbg.gdblib.prompt
    import pwndbg.gdblib.regs
    import pwndbg.gdblib.typeinfo
