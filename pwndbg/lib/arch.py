import struct
import sys
from typing import *


class Arch:
    def __init__(self, arch_name, ptrsize, endian):
        self.name = arch_name
        # TODO: `current` is the old name for the arch name, and it's now an
        # alias for `name`. It's used throughout the codebase, do we want to
        # migrate these uses to `name`?
        self.current = self.name
        self.ptrsize = ptrsize
        self.ptrmask = (1 << 8 * ptrsize) - 1
        self.endian = endian

        self.fmt = {
            (4, "little"): "<I",
            (4, "big"): ">I",
            (8, "little"): "<Q",
            (8, "big"): ">Q",
        }.get((self.ptrsize, self.endian))

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.name == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

        self.native_endian = str(sys.byteorder)

    def pack(self, integer):  # type: (int) -> bytes
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data):  # type: (bytes) -> int
        return struct.unpack(self.fmt, data)[0]

    def signed(self, integer):  # type: (int) -> int
        return self.unpack(self.pack(integer), signed=True)  # type: ignore

    def unsigned(self, integer):  # type: (int) -> int
        return self.unpack(self.pack(integer))
