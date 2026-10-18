from __future__ import annotations

import ctypes
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

import pwndbg.aglib.memory
from pwndbg.dbg_mod import Value
from pwndbg.lib.memory import Page


class ArchMisc:
    def kthread_stack(self, thread: Value) -> int | None:
        return None

    def _get_pt_regs(
        self, copy: Callable[[ReadableBuffer, int], ctypes.Structure], page: Page, size: int
    ) -> list[tuple[str, int]]:
        start = page.end - size
        regs = copy(pwndbg.aglib.memory.read(start, size), 0)
        regs = [(name, int(getattr(regs, name))) for name, *_ in regs._fields_]
        return regs

    def pt_regs(self, page: Page) -> tuple[list[tuple[str, int]] | None, str | None]:
        return None, None
