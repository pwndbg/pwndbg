"""
Getting Thread Local Storage (TLS) information.
"""

from __future__ import annotations

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap


def __call_pthread_self() -> int:
    """
    Retrieve the address of the `struct pthread_t` for the current thread by
    calling pthread_self(). This address can be used to locate the base address
    of the Thread Local Storage (TLS).
    """
    if pwndbg.aglib.symbol.lookup_symbol_addr("pthread_self") is None:
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
    """
    Get the base address of the Thread Local Storage (TLS) for the current thread using
    the pthread_self() function. The returned address points to the `struct tcbhead_t`,
    which serves as the header for TLS and thread-specific metadata.
    """
    if pwndbg.aglib.arch.name not in ("x86-64", "i386", "arm", "aarch64", "loongarch64"):
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
    # loongarch64: https://github.com/bminor/glibc/blob/1c9ac027a5deb6c3e026be0e88d38959529e6102/sysdeps/loongarch/nptl/tls.h#L64
    # For i386 and x86-64, the return value of the pthread_self() is the address of TLS, because the value is self reference of the TLS: https://elixir.bootlin.com/glibc/glibc-2.37/source/nptl/pthread_create.c#L671
    # But for arm, the implementation of THREAD_SELF is different, we need to add sizeof(struct pthread) to the result to get the address of TLS.

    if pwndbg.aglib.arch.name in ("arm", "aarch64"):
        pthread_type = pwndbg.aglib.typeinfo.load("struct pthread")
        if pthread_type is None:
            # Type 'pthread' not found
            return 0
        result += pthread_type.sizeof
    elif pwndbg.aglib.arch.name == "loongarch64":
        pthread_type = pwndbg.aglib.typeinfo.load("struct pthread")
        if pthread_type is None:
            # Type 'pthread' not found
            return 0
        result += pthread_type.sizeof + pthread_type.alignof

    return result


def find_address_with_register() -> int:
    """
    Get the base address of the Thread Local Storage (TLS) for the current thread using
    a CPU register. The returned address points to the `struct tcbhead_t`, which is the
    entry point for TLS and thread-specific metadata.
    """
    if pwndbg.aglib.arch.name == "x86-64":
        return int(pwndbg.aglib.regs.fsbase)
    elif pwndbg.aglib.arch.name == "i386":
        return int(pwndbg.aglib.regs.gsbase)
    elif pwndbg.aglib.arch.name == "aarch64":
        # FIXME: cleanup/remove `TPIDR_EL0` register, it was renamed to `tpidr` since GDB13+
        return int(pwndbg.aglib.regs.tpidr or pwndbg.aglib.regs.TPIDR_EL0 or 0)
    elif pwndbg.aglib.arch.name == "arm":
        # TODO: linux ptrace for 64bit kernel?
        # In FreeBSD tls is under `tpidruro` register.
        # In Linux, the `tpidruro` register isn't available via ptrace in the 32-bit
        # kernel but it is available for an aarch32 program running under an arm64
        # kernel via the ptrace compat interface.
        return int(pwndbg.aglib.regs.tpidruro or 0)
    elif pwndbg.aglib.arch.name == "loongarch64":
        return int(pwndbg.aglib.regs.tp or 0)
    return 0
