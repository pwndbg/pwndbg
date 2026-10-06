from __future__ import annotations

import pathlib
from enum import Enum
from typing import Protocol
from pwndbg.lib.err import Status

from pwndbg.lib.arch import ArchDefinition


class CompilerType(Enum):
    ZIG = "zig"
    CLANG = "clang"
    GCC = "gcc"


class Compiler(Protocol):
    def type(self) -> CompilerType:
        """
        Which compiler are we using?
        """
        ...

    def invocation_with_target(self, arch: ArchDefinition) -> list[str]:
        """
        The command line arguments to invoke the compiler on architecture `arch`.

        Note: The arch argument must be pwndbg.aglib.arch since only the current
        arch object (the process target architecture) is validly constructed
        (fixme: #3534).

        Raises:
            DependencyNotFoundError: if the compiler is not present, is on an
                unsupported version, or does not support the target arch we need
        """
        ...
