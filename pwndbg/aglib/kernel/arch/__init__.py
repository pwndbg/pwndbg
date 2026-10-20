from __future__ import annotations

import pwndbg
import pwndbg.aglib
from pwndbg.dbg_mod import Value
from pwndbg.lib.memory import Page

from .aarch64.misc import aarch64Misc
from .aarch64.paging import aarch64Paging
from .aarch64.symbol import aarch64Symbols
from .i386.paging import i386Paging
from .misc import ArchMisc
from .paging import Paging
from .rv64.paging import rv64Paging
from .symbol import ArchSymbols
from .x86_64.misc import x86_64Misc
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
    return Paging()


def select_symbol() -> ArchSymbols:
    match pwndbg.aglib.arch.name:
        case "aarch64":
            return aarch64Symbols()
        case "x86-64":
            return x86_64Symbols()
    return ArchSymbols()


def pt_regs(page: Page) -> tuple[list[tuple[str, int]] | None, str | None]:
    misc = ArchMisc()
    match pwndbg.aglib.arch.name:
        case "aarch64":
            misc = aarch64Misc()
        case "x86-64":
            misc = x86_64Misc()
    return misc.pt_regs(page)


def kthread_stack(thread: Value) -> int | None:
    misc = ArchMisc()
    match pwndbg.aglib.arch.name:
        case "aarch64":
            misc = aarch64Misc()
        case "x86-64":
            misc = x86_64Misc()
    return misc.kthread_stack(thread)
