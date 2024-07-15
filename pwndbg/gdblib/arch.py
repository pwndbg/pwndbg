from __future__ import annotations

from typing import Literal

import gdb
import pwnlib

import pwndbg.gdblib
from pwndbg.gdblib import typeinfo
from pwndbg.lib.arch import Arch

# TODO: x86-64 needs to come before i386 in the current implementation, make
# this order-independent
ARCHS = (
    "x86-64",
    "i386",
    "aarch64",
    "mips",
    "powerpc",
    "sparc",
    "arm",
    "armcm",
    "riscv:rv32",
    "riscv:rv64",
    "riscv",
)


# mapping between gdb and pwntools arch names
pwnlib_archs_mapping = {
    "x86-64": "amd64",
    "i386": "i386",
    "aarch64": "aarch64",
    "mips": "mips",
    "powerpc": "powerpc",
    "sparc": "sparc",
    "arm": "arm",
    "iwmmxt": "arm",
    "armcm": "thumb",
    "rv32": "riscv32",
    "rv64": "riscv64",
}


def read_thumb_bit() -> int | None:
    """
    Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

    Return None if the Thumb bit is not relevent to the current architecture
    """
    if pwndbg.gdblib.arch.current == "arm":
        # When program initially starts, cpsr may not be readable
        if (cpsr := pwndbg.gdblib.regs.cpsr) is not None:
            return (cpsr >> 5) & 1
    elif pwndbg.gdblib.arch.current == "armcm":
        # ARM Cortex-M procesors only suport Thumb mode. However, there is still a bit
        # that represents the Thumb mode (which is currently architecturally defined to be 1)
        if (xpsr := pwndbg.gdblib.regs.xpsr) is not None:
            return (xpsr >> 24) & 1
    # AArch64 does not have a Thumb bit
    return None


def get_thumb_mode_string() -> Literal["arm", "thumb"] | None:
    thumb_bit = read_thumb_bit()
    return None if thumb_bit is None else "thumb" if thumb_bit == 1 else "arm"


arch = Arch("i386", typeinfo.ptrsize, "little")

name: str
ptrsize: int
ptrmask: int
endian: Literal["little", "big"]


def _get_arch(ptrsize: int):
    not_exactly_arch = False

    if "little" in gdb.execute("show endian", to_string=True).lower():
        endian = "little"
    else:
        endian = "big"

    # Importing requires that `pwndbg.dbg` already be set up, so we have to do
    # it here, rather then on the top level.
    import pwndbg.gdblib.proc

    if pwndbg.gdblib.proc.alive:
        arch = gdb.newest_frame().architecture().name()
    else:
        arch = gdb.execute("show architecture", to_string=True).strip()
        not_exactly_arch = True

    # Below, we fix the fetched architecture
    for match in ARCHS:
        if match in arch:
            # Distinguish between Cortex-M and other ARM
            if match == "arm" and "-m" in arch:
                match = "armcm"
            elif match.startswith("riscv:"):
                match = match[6:]
            elif match == "riscv":
                # If GDB doesn't detect the width, it will just say `riscv`.
                match = "rv64"
            return match, ptrsize, endian

    if not_exactly_arch:
        raise RuntimeError(f"Could not deduce architecture from: {arch}")

    return arch, ptrsize, endian


def update() -> None:
    arch_name, ptrsize, endian = _get_arch(typeinfo.ptrsize)
    arch.update(arch_name, ptrsize, endian)
    pwnlib.context.context.arch = pwnlib_archs_mapping[arch_name]
    pwnlib.context.context.bits = ptrsize * 8
