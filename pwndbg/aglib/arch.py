from __future__ import annotations

import pwndbg
from pwndbg.lib.arch import Arch

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


arch: Arch = Arch("i386", 4, "little")


def update() -> None:
    a = pwndbg.dbg.selected_inferior().arch()
    arch.update(a.name, a.ptrsize, a.endian)
