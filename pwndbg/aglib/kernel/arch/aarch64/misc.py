from __future__ import annotations

import ctypes

import pwndbg.aglib.kernel
from pwndbg.dbg_mod import Value
from pwndbg.lib.memory import Page

from ..misc import ArchMisc


class pt_regs_aarch64(ctypes.Structure):
    _fields_ = (
        ("x0", ctypes.c_uint64),
        ("x1", ctypes.c_uint64),
        ("x2", ctypes.c_uint64),
        ("x3", ctypes.c_uint64),
        ("x4", ctypes.c_uint64),
        ("x5", ctypes.c_uint64),
        ("x6", ctypes.c_uint64),
        ("x7", ctypes.c_uint64),
        ("x8", ctypes.c_uint64),
        ("x9", ctypes.c_uint64),
        ("x10", ctypes.c_uint64),
        ("x11", ctypes.c_uint64),
        ("x12", ctypes.c_uint64),
        ("x13", ctypes.c_uint64),
        ("x14", ctypes.c_uint64),
        ("x15", ctypes.c_uint64),
        ("x16", ctypes.c_uint64),
        ("x17", ctypes.c_uint64),
        ("x18", ctypes.c_uint64),
        ("x19", ctypes.c_uint64),
        ("x20", ctypes.c_uint64),
        ("x21", ctypes.c_uint64),
        ("x22", ctypes.c_uint64),
        ("x23", ctypes.c_uint64),
        ("x24", ctypes.c_uint64),
        ("x25", ctypes.c_uint64),
        ("x26", ctypes.c_uint64),
        ("x27", ctypes.c_uint64),
        ("x28", ctypes.c_uint64),
        ("x29", ctypes.c_uint64),
        ("x30", ctypes.c_uint64),
        ("sp", ctypes.c_uint64),
        ("pc", ctypes.c_uint64),
        ("pstate", ctypes.c_uint64),
        ("orig_x0", ctypes.c_uint64),
        ("syscallno", ctypes.c_int32),  # ends at offset 0x11c but the struct is 0x120 bytes
    )


class aarch64Misc(ArchMisc):
    def kthread_stack(self, thread: Value) -> int | None:
        if thread.dereference().type.has_field("thread"):
            return int(thread["thread"]["cpu_context"]["sp"])
        if thread.dereference().type.has_field("stack"):
            return int(thread["stack"])
        # the offset of stack was not recovered
        return None

    def pt_regs(self, page: Page) -> tuple[list[tuple[str, int]] | None, str | None]:
        size = ctypes.sizeof(pt_regs_aarch64)
        kversion = pwndbg.aglib.kernel.krelease()
        if kversion and (5, 10) <= kversion < (6, 18):
            size += 0x10
        regs = self._get_pt_regs(pt_regs_aarch64.from_buffer_copy, page, size)
        return regs, "syscallno"
