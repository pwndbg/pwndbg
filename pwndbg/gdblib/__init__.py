# The `arch` module can be accessed with `from pwndbg.gdblib.arch import arch_mod`,
# while `pwndbg.gdblib.arch` will represent the `Arch` object
from pwndbg.gdblib import arch as arch_mod
from pwndbg.gdblib.arch import arch

__all__ = ["ctypes", "memory", "typeinfo"]
