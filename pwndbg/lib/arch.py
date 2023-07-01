import struct
import sys
from typing import Optional

from typing_extensions import Literal


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

        if self.endian == "little":
            self.fmts = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
        else:
            self.fmts = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.name == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

    def pack(self, integer: int, size: Optional[int] = None) -> bytes:
        fmt = self._get_fmt(size)
        return struct.pack(fmt, integer & self.ptrmask)

    def unpack(self, data: bytes, size: Optional[int] = None) -> int:
        fmt = self._get_fmt(size)
        return struct.unpack(fmt, data)[0]

    def _get_fmt(self, size: Optional[int]) -> str:
        if size is None:
            size = self.ptrsize
        return self.fmts[size]
