from __future__ import annotations

import ctypes

from pwndbg.dbg_mod import Value
from pwndbg.lib.memory import Page

from ..misc import ArchMisc


class pt_regs_x86_64(ctypes.Structure):
    _fields_ = (
        ("r15", ctypes.c_ulong),
        ("r14", ctypes.c_ulong),
        ("r13", ctypes.c_ulong),
        ("r12", ctypes.c_ulong),
        ("rbp", ctypes.c_ulong),
        ("rbx", ctypes.c_ulong),
        ("r11", ctypes.c_ulong),
        ("r10", ctypes.c_ulong),
        ("r9", ctypes.c_ulong),
        ("r8", ctypes.c_ulong),
        ("rax", ctypes.c_ulong),
        ("rcx", ctypes.c_ulong),
        ("rdx", ctypes.c_ulong),
        ("rsi", ctypes.c_ulong),
        ("rdi", ctypes.c_ulong),
        ("orig_ax", ctypes.c_ulong),
        ("rip", ctypes.c_ulong),
        ("cs", ctypes.c_uint64),
        ("flags", ctypes.c_ulong),
        ("rsp", ctypes.c_ulong),
        ("ss", ctypes.c_uint64),
    )


class x86_64Misc(ArchMisc):
    def kthread_stack(self, thread: Value) -> int | None:
        if thread.dereference().type.has_field("thread"):
            return int(thread["thread"]["sp"])
        if thread.dereference().type.has_field("stack"):
            return int(thread["stack"])
        # the offset of stack was not recovered
        return None

    def pt_regs(self, page: Page) -> tuple[list[tuple[str, int]] | None, str | None]:
        size = ctypes.sizeof(pt_regs_x86_64)
        regs = self._get_pt_regs(pt_regs_x86_64.from_buffer_copy, page, size)
        return regs, "orig_ax"
