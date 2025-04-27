from __future__ import annotations

import typing
from dataclasses import dataclass
from dataclasses import field
from enum import Enum
from enum import auto
from typing import List
from typing import Literal

from capstone import CS_MODE_MICRO
from capstone import CS_MODE_MIPS1
from capstone import CS_MODE_MIPS2
from capstone import CS_MODE_MIPS3
from capstone import CS_MODE_MIPS4
from capstone import CS_MODE_MIPS5
from capstone import CS_MODE_MIPS32
from capstone import CS_MODE_MIPS32R2
from capstone import CS_MODE_MIPS32R3
from capstone import CS_MODE_MIPS32R5
from capstone import CS_MODE_MIPS32R6
from capstone import CS_MODE_MIPS64
from capstone import CS_MODE_MIPS64R2
from capstone import CS_MODE_MIPS64R3
from capstone import CS_MODE_MIPS64R5
from capstone import CS_MODE_MIPS64R6
from capstone import CS_MODE_NANOMIPS

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


# The platform being debugged
class Platform(Enum):
    LINUX = (auto(),)
    DARWIN = (auto(),)
    # WINDOWS = auto(),
    # ANDROID = auto(),
    # OPENBSD = auto(),
    # FREEBSD = auto(),


PWNLIB_PLATFORM_MAPPINGS: dict[Platform, str] = {
    Platform.LINUX: "linux",
    Platform.DARWIN: "darwin",
}


# A series of tuples
# Index 0 = Unique integer
# Index 1 = Capstone constant associated with the attribute
class ArchAttribute(Enum):
    # MIPS ATTRIBUTES
    ## MIPS created and removed lots of instructions between ISA versions, sometimes re-using
    ## old instruction encodings. To disassemble correctly, we need to choose the correct ISA.
    MIPS_ISA_1 = auto(), CS_MODE_MIPS1
    MIPS_ISA_2 = auto(), CS_MODE_MIPS2
    MIPS_ISA_3 = auto(), CS_MODE_MIPS3
    MIPS_ISA_4 = auto(), CS_MODE_MIPS4
    MIPS_ISA_5 = auto(), CS_MODE_MIPS5

    MIPS_ISA_32 = auto(), CS_MODE_MIPS32
    MIPS_ISA_32R2 = auto(), CS_MODE_MIPS32R2

    MIPS_ISA_32R3 = auto(), CS_MODE_MIPS32R3
    MIPS_ISA_32R5 = auto(), CS_MODE_MIPS32R5
    MIPS_ISA_32R6 = auto(), CS_MODE_MIPS32R6

    MIPS_ISA_64 = auto(), CS_MODE_MIPS64
    MIPS_ISA_64R2 = auto(), CS_MODE_MIPS64R2
    MIPS_ISA_64R3 = auto(), CS_MODE_MIPS64R3
    MIPS_ISA_64R5 = auto(), CS_MODE_MIPS64R5
    MIPS_ISA_64R6 = auto(), CS_MODE_MIPS64R6

    MIPS_ISA_MICRO = auto(), CS_MODE_MICRO
    MIPS_ISA_NANO = auto(), CS_MODE_NANOMIPS

    def __init__(self, _, cs_mode):
        self.cs_mode = cs_mode


@dataclass
class ArchDefinition:
    name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
    ptrsize: int
    """Pointer size in bytes"""
    endian: Literal["little", "big"]
    platform: Platform
    attributes: List[ArchAttribute] = field(default_factory=list)
