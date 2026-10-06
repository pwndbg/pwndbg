"""
We need a compiler to assemble shellcode and add structures into the debugee.

This module provides an API to a compiler, without exposing which compiler
is being used underneath.

In order we try for: zig, clang, gcc.
"""
from __future__ import annotations

from .dispatch import Compiler
from .dispatch import ToolchainInvocation
from .facade import AssemblingError
from .facade import which
from .facade import asm
from .facade import compile_program
from .facade import invocation
from .facade import objcopy_invocation

__all__ = [
    "which",
    "asm",
    "compile_program",
    "invocation",
    "objcopy_invocation",
    "Compiler",
    "ToolchainInvocation",
    "AssemblingError"
]
