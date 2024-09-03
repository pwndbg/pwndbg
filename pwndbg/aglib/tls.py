"""
Getting Thread Local Storage (TLS) information.
"""

from __future__ import annotations

import pwndbg.aglib.arch
import pwndbg.aglib.disasm
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap


def __call_pthread_self() -> int:
    """Get the address of TLS by calling pthread_self()."""
    if pwndbg.dbg.selected_inferior().symbol_address_from_name("pthread_self") is None:
        return 0
    try:
        return int(
            pwndbg.dbg.selected_frame().evaluate_expression(
                "(void *)pthread_self()", lock_scheduler=True
            )
        )
    except pwndbg.dbg_mod.Error:
        return 0


def find_address_with_pthread_self() -> int:
    """Get the address of TLS with pthread_self()."""
    if pwndbg.aglib.arch.current not in ("x86-64", "i386", "arm"):
        # Note: we should support aarch64 if it's possible that TPIDR_EL0 register can not be accessed.
        return 0
    result = __call_pthread_self()
    if result <= 0:
        # pthread_self() is not valid
        return 0

    # pthread_self() is defined as: https://elixir.bootlin.com/glibc/glibc-2.37/source/nptl/pthread_self.c#L22
    # THREAD_SELF is defined as:
    # i386: https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/i386/nptl/tls.h#L234
    # x86-64: https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/x86_64/nptl/tls.h#L181
    # arm: https://elixir.bootlin.com/glibc/latest/source/sysdeps/arm/nptl/tls.h#L76
    # For i386 and x86-64, the return value of the pthread_self() is the address of TLS, because the value is self reference of the TLS: https://elixir.bootlin.com/glibc/glibc-2.37/source/nptl/pthread_create.c#L671
    # But for arm, the implementation of THREAD_SELF is different, we need to add sizeof(struct pthread) to the result to get the address of TLS.

    if pwndbg.aglib.arch.current == "arm":
        # 0x4c0 is sizeof(struct pthread)
        # TODO: we might need to adjust the value if the size of struct pthread is changed in the future.
        result += 0x4C0
    return result


def find_address_with_register() -> int:
    """Get the address of TLS with register."""
    if pwndbg.aglib.arch.current == "x86-64":
        return int(pwndbg.aglib.regs.fsbase)
    elif pwndbg.aglib.arch.current == "i386":
        return int(pwndbg.aglib.regs.gsbase)
    elif pwndbg.aglib.arch.current == "aarch64":
        return int(pwndbg.aglib.regs.TPIDR_EL0)
    # TODO: is it possible that we can get the address of TLS with register on arm?
    return 0
