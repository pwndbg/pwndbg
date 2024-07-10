from __future__ import annotations

import struct
import sys
from typing import Literal

FMT_LITTLE_ENDIAN = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
FMT_BIG_ENDIAN = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}


class Arch:
    def __init__(self, arch_name: str, ptrsize: int, endian: Literal["little", "big"]) -> None:
        self.update(arch_name, ptrsize, endian)
        self.native_endian = str(sys.byteorder)

    def update(self, arch_name: str, ptrsize: int, endian: Literal["little", "big"]) -> None:
        self.name = arch_name
        # TODO: `current` is the old name for the arch name, and it's now an
        # alias for `name`. It's used throughout the codebase, do we want to
        # migrate these uses to `name`?
        self.current = self.name
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
