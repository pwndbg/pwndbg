from __future__ import annotations

import struct
import sys
import typing
from typing import Literal

# Names of arches that Pwndbg supports
# The names that GDB/LLDB recognize are converted to a name in this list
PWNDBG_SUPPORTED_ARCHITECTURES_TYPE = Literal[
    "x86-64",
    "i386",
    "i8086",
    "mips",
    "aarch64",
    "arm",
    "armcm",
    "rv32",
    "rv64",
    "sparc",
    "powerpc",
    "loongarch64",
    "s390x",
]

PWNDBG_SUPPORTED_ARCHITECTURES: list[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE] = list(
    typing.get_args(PWNDBG_SUPPORTED_ARCHITECTURES_TYPE)
)

# mapping between pwndbg and pwntools arch names
PWNLIB_ARCH_MAPPINGS = {
    "x86-64": "amd64",
    "i386": "i386",
    "i8086": "none",
    "mips": "mips",
    "aarch64": "aarch64",
    "arm": "arm",
    "armcm": "thumb",
    "rv32": "riscv32",
    "rv64": "riscv64",
    "powerpc": "powerpc",
    "sparc": "sparc",
    "loongarch64": "none",
    "s390x": "s390",  # FIXME: I believe this should be s390x, but that's not supported
}


FMT_LITTLE_ENDIAN = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
FMT_BIG_ENDIAN = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}


class Arch:
    def __init__(
        self,
        arch_name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE,
        ptrsize: int,
        endian: Literal["little", "big"],
    ) -> None:
        self.update(arch_name, ptrsize, endian)
        self.native_endian = str(sys.byteorder)

    def update(
        self,
        arch_name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE,
        ptrsize: int,
        endian: Literal["little", "big"],
    ) -> None:
        self.name = arch_name
        self.ptrsize = ptrsize
        self.ptrmask = (1 << 8 * ptrsize) - 1
        self.endian = endian

        self.fmts = FMT_LITTLE_ENDIAN if endian == "little" else FMT_BIG_ENDIAN
        self.fmt = self.fmts[self.ptrsize]

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.endian == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]

    def pack_size(self, integer: int, size: int) -> bytes:
        return struct.pack(self.fmts[size], integer & self.ptrmask)

    def unpack_size(self, data: bytes, size: int) -> int:
        return struct.unpack(self.fmts[size], data)[0]
