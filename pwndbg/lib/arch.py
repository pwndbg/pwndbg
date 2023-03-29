import struct
import sys

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

        self.fmt = {(4, "little"): "<I", (4, "big"): ">I", (8, "little"): "<Q", (8, "big"): ">Q"}[
            (self.ptrsize, self.endian)
        ]

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.name == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]
