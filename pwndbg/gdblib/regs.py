"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""

from __future__ import annotations

import ctypes
import re
import sys
from types import ModuleType
from typing import Any
from typing import Dict
from typing import Generator
from typing import List
from typing import Tuple

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.proc
import pwndbg.gdblib.remote
import pwndbg.lib.cache
from pwndbg.lib.regs import BitFlags
from pwndbg.lib.regs import RegisterSet
from pwndbg.lib.regs import reg_sets


@pwndbg.gdblib.proc.OnlyWhenRunning
def gdb_get_register(name: str) -> gdb.Value:
    frame = gdb.selected_frame()
    try:
        return frame.read_register(name)
    except ValueError:
        return frame.read_register(name.upper())


# We need to manually make some ptrace calls to get fs/gs bases on Intel
PTRACE_ARCH_PRCTL = 30
ARCH_GET_FS = 0x1003
ARCH_GET_GS = 0x1004


class module(ModuleType):
    previous: dict[str, int] = {}
    last: dict[str, int] = {}

    @pwndbg.lib.cache.cache_until("stop", "prompt")
    def __getattr__(self, attr: str) -> int | None:
        attr = attr.lstrip("$")
        try:
            value = gdb_get_register(attr)
            if value is None and attr.lower() == "xpsr":
                value = gdb_get_register("xPSR")
            size = pwndbg.gdblib.typeinfo.unsigned.get(
                value.type.sizeof, pwndbg.gdblib.typeinfo.ulong
            )
            value = value.cast(size)
            if attr == "pc" and pwndbg.gdblib.arch.current == "i8086":
                value += self.cs * 16
            return int(value) & pwndbg.gdblib.arch.ptrmask
        except (ValueError, gdb.error):
            return None

    def __setattr__(self, attr: str, val: Any) -> None:
        if attr in ("last", "previous"):
            super().__setattr__(attr, val)
        else:
            # Not catching potential gdb.error as this should never
            # be called in a case when this can throw
            gdb.execute(f"set ${attr} = {val}")

    @pwndbg.lib.cache.cache_until("stop", "prompt")
    def __getitem__(self, item: str) -> int | None:
        if not isinstance(item, str):
            print("Unknown register type: %r" % (item))
            return None

        # e.g. if we're looking for register "$rax", turn it into "rax"
        item = item.lstrip("$")
        item = getattr(self, item.lower())

        if item is not None:
            item &= pwndbg.gdblib.arch.ptrmask

        return item

    def __contains__(self, reg) -> bool:
        regs = set(reg_sets[pwndbg.gdblib.arch.current]) | {"pc", "sp"}
        return reg in regs

    def __iter__(self):
        regs = set(reg_sets[pwndbg.gdblib.arch.current]) | {"pc", "sp"}
        yield from regs

    @property
    def current(self) -> RegisterSet:
        return reg_sets[pwndbg.gdblib.arch.current]

    # TODO: All these should be able to do self.current
    @property
    def gpr(self) -> Tuple[str, ...]:
        return reg_sets[pwndbg.gdblib.arch.current].gpr

    @property
    def common(self) -> List[str]:
        return reg_sets[pwndbg.gdblib.arch.current].common

    @property
    def frame(self) -> str:
        return reg_sets[pwndbg.gdblib.arch.current].frame

    @property
    def retaddr(self) -> Tuple[str, ...]:
        return reg_sets[pwndbg.gdblib.arch.current].retaddr

    @property
    def flags(self) -> Dict[str, BitFlags]:
        return reg_sets[pwndbg.gdblib.arch.current].flags

    @property
    def extra_flags(self) -> Dict[str, BitFlags]:
        return reg_sets[pwndbg.gdblib.arch.current].extra_flags

    @property
    def stack(self) -> str:
        return reg_sets[pwndbg.gdblib.arch.current].stack

    @property
    def retval(self) -> str:
        return reg_sets[pwndbg.gdblib.arch.current].retval

    @property
    def all(self):
        regs = reg_sets[pwndbg.gdblib.arch.current]
        retval: list[str] = []
        for regset in (
            regs.pc,
            regs.stack,
            regs.frame,
            regs.retaddr,
            regs.flags,
            regs.gpr,
            regs.misc,
        ):
            if regset is None:
                continue

            if isinstance(regset, (list, tuple)):  # regs.retaddr
                retval.extend(regset)
            elif isinstance(regset, dict):  # regs.flags
                retval.extend(regset.keys())
            else:
                retval.append(regset)  # type: ignore[arg-type]
        return retval

    def fix(self, expression: str) -> str:
        for regname in set(self.all + ["sp", "pc"]):
            expression = re.sub(rf"\$?\b{regname}\b", r"$" + regname, expression)
        return expression

    def items(self) -> Generator[Tuple[str, Any], None, None]:
        for regname in self.all:
            yield regname, self[regname]

    reg_sets = reg_sets

    @property
    def changed(self) -> List[str]:
        delta = []
        for reg, value in self.previous.items():
            if self[reg] != value:
                delta.append(reg)
        return delta

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def fsbase(self) -> int:
        return self._fs_gs_helper("fs_base", ARCH_GET_FS)

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def gsbase(self) -> int:
        return self._fs_gs_helper("gs_base", ARCH_GET_GS)

    @pwndbg.lib.cache.cache_until("stop")
    def _fs_gs_helper(self, regname: str, which) -> int:
        """Supports fetching based on segmented addressing, a la fs:[0x30].
        Requires ptrace'ing the child directory if i386."""

        if pwndbg.gdblib.arch.current == "x86-64":
            return int(gdb_get_register(regname))

        # We can't really do anything if the process is remote.
        if pwndbg.gdblib.remote.is_remote():
            return 0

        # Use the lightweight process ID
        pid, lwpid, tid = gdb.selected_thread().ptid

        # Get the register
        ppvoid = ctypes.POINTER(ctypes.c_void_p)
        value = ppvoid(ctypes.c_void_p())
        value.contents.value = 0

        libc = ctypes.CDLL("libc.so.6")
        result = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, which)

        if result == 0:
            return (value.contents.value or 0) & pwndbg.gdblib.arch.ptrmask

        return 0

    def __repr__(self) -> str:
        return "<module pwndbg.gdblib.regs>"


# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, "")


@pwndbg.gdblib.events.cont
@pwndbg.gdblib.events.stop
def update_last() -> None:
    M: module = sys.modules[__name__]
    M.previous = M.last
    M.last = {k: M[k] for k in M.common}
    if pwndbg.gdblib.config.show_retaddr_reg:
        M.last.update({k: M[k] for k in M.retaddr})
