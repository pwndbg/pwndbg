from __future__ import annotations

import typing
from dataclasses import dataclass
from enum import Enum
from enum import auto
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


# The platform being debugged
class Platform(Enum):
    LINUX = (auto(),)
    DARWIN = (auto(),)
    # WINDOWS = auto(),
    # ANDROID = auto(),
    # OPENBSD = auto(),
    # FREEBSD = auto(),


PWNLIB_PLATFORM_MAPPINGS: dict[Platform,str] = {
    Platform.LINUX: "linux",
    Platform.DARWIN: "darwin",
}

@dataclass
class ArchDefinition:
    name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
    name_raw: str  # The raw string returned by the debugger
    ptrsize: int
    endian: Literal["little", "big"]
    platform: Platform
