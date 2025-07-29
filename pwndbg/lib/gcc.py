"""
Functions for determining the architecture-dependent path to
GCC and any flags it should be executed with.
"""

from __future__ import annotations

import glob
import os
import platform
from typing import Any
from typing import List

import pwnlib

from pwndbg.lib.arch import ArchDefinition

printed_message = False


def which(arch: ArchDefinition) -> List[str]:
    try:
        gcc = pwnlib.asm.which_binutils("g++")
    except pwnlib.exception.PwnlibException as _:
        raise ValueError("Couldn't find g++ for the current architecture.")

    return [gcc] + _flags(arch.name)


def _flags(arch_name: str) -> List[str]:
    if arch_name == "i386":
        return ["-m32"]
    if arch_name.endswith("x86-64"):
        return ["-m64"]

    return []
