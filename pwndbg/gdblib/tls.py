"""
Getting Thread Local Storage (TLS) information.
"""
import sys
from contextlib import contextmanager
from types import ModuleType

import gdb

import pwndbg.disasm
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.gdblib.vmmap


@contextmanager
def lock_scheduler():
    already_lock = gdb.parameter("scheduler-locking") == "on"
    old_config = gdb.parameter("scheduler-locking")
    if not already_lock:
        gdb.execute("set scheduler-locking on")
    yield
    if not already_lock:
        gdb.execute("set scheduler-locking %s" % old_config)


class module(ModuleType):
    """Getting Thread Local Storage (TLS) information."""

    lock_scheduler = staticmethod(lock_scheduler)

    def is_thread_local_variable_offset(self, offset: int) -> bool:
        """Check if the offset to TLS is a valid offset for the heap heuristics."""
        if pwndbg.gdblib.arch.current in ("x86-64", "i386"):
            is_valid = 0 < -offset < 0x250
        else:  # elif pwndbg.gdblib.arch.current in ("aarch64", "arm"):
            is_valid = 0 < offset < 0x250
        # check alignment
        return is_valid and offset % pwndbg.gdblib.arch.ptrsize == 0

    def is_thread_local_variable(self, addr: int) -> bool:
        """Check if the address is a valid thread local variable's address for the heap heuristics."""
        if not self.address:
            # Since we can not get the TLS base address, we trust that the address is valid.
            return True
        return self.is_thread_local_variable_offset(
            addr - self.address
        ) and addr in pwndbg.gdblib.vmmap.find(self.address)

    def call_pthread_self(self) -> int:
        """Get the address of TLS by calling pthread_self()."""
        if pwndbg.gdblib.symbol.address("pthread_self") is None:
            return 0
        with lock_scheduler():
            try:
                return int(gdb.parse_and_eval("(void *)pthread_self()"))
            except gdb.error:
                return 0

    @property
    def address(self) -> int:
        """Get the base address of TLS."""
        tls_base = 0

        if pwndbg.gdblib.arch.current == "x86-64":
            tls_base = int(pwndbg.gdblib.regs.fsbase)
        elif pwndbg.gdblib.arch.current == "i386":
            tls_base = int(pwndbg.gdblib.regs.gsbase)
        elif pwndbg.gdblib.arch.current == "aarch64":
            tls_base = int(pwndbg.gdblib.regs.TPIDR_EL0)

        # Sometimes, we need to get TLS base via pthread_self() for the following reason:
        # For x86-64, fsbase might be 0 if we are remotely debugging and the GDB version <= 8.X
        # For i386, gsbase might be 0 if we are remotely debugging
        # For other archs, we can't get the TLS base address via register
        # Note: aarch64 seems doesn't have this issue
        return tls_base if tls_base else self.call_pthread_self()


# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, "")
