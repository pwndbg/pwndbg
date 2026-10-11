from __future__ import annotations

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.kernel.arch

from .aarch64.paging import aarch64Paging
from .aarch64.symbol import Aarch64Symbols
from .i386.paging import i386Paging
from .paging import Paging
from .rv64.paging import rv64Paging
from .symbol import ArchSymbols
from .x86_64.paging import x86_64Paging
from .x86_64.symbol import x86_64Symbols


def select_paging() -> Paging:
    match pwndbg.aglib.arch.name:
        case "aarch64":
            return aarch64Paging()
        case "x86-64":
            return x86_64Paging()
        case "i386":
            return i386Paging()
        case "rv64":
            return rv64Paging()
        case _:
            raise NotImplementedError(f"{pwndbg.aglib.arch.name} is not supported")


def select_symbol() -> ArchSymbols:
    match pwndbg.aglib.arch.name:
        case "aarch64":
            return Aarch64Symbols()
        case "x86-64":
            return x86_64Symbols()
        case _:
            raise NotImplementedError()
