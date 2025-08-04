from __future__ import annotations

import struct
import types


class MockAmd64Arch(types.ModuleType):
    def __init__(self, module_name):
        super().__init__(module_name)

        self.ptrsize = 8
        self.ptrmask = (1 << 8 * self.ptrsize) - 1
        self.endian = "little"
        self.fmt = "<Q"

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]
