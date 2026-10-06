from __future__ import annotations

from pathlib import Path

from pwndbg.lib.arch import ArchDefinition

from . import clang
from . import gcc
from . import zig
from .dispatch import Compiler

# Order is important.
_compilers: tuple[Compiler, ...] = (zig, clang, gcc)

def asm(self, arch: ArchDefinition, data: str, includes: list[Path] | None = None) -> bytes:
    """
    Assemble the `data` string for the passed architecture and return the assembled bytes.

    NOTE: As is in pwndbg, an ArchDefinition is only valid for the current architecture,
    so you can only pass in pwndbg.aglib.arch. (FIXME)
    """
    ...

def invocation(self, compiler_flags: list[str]) -> list[str]:
    """
    Return the command line invocation for running the compiler with
    `compiler_flags` flags against the architecture that is currently being debugged.
    """
    ...
