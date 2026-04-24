"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""

from __future__ import annotations

import ctypes
import re
from collections.abc import Generator
from collections.abc import Iterator
from typing import Any

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.proc
import pwndbg.aglib.remote
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg.dbg_mod import EventType
from pwndbg.lib.regs import BitFlags
from pwndbg.lib.regs import KernelRegisterSet
from pwndbg.lib.regs import RegisterSet
from pwndbg.lib.regs import reg_sets

# We need to manually make some ptrace calls to get fs/gs bases on Intel
PTRACE_ARCH_PRCTL = 30
ARCH_GET_FS = 0x1003
ARCH_GET_GS = 0x1004


class RegisterManager:
    previous: dict[str, int | None] = {}
    last: dict[str, int | None] = {}

    @pwndbg.lib.cache.cache_until("stop")
    def regs_in_frame(self, frame: pwndbg.dbg_mod.Frame) -> pwndbg.dbg_mod.Registers:
        return frame.regs()

    @pwndbg.aglib.proc.OnlyWhenRunning
    def get_register(self, name: str, frame: pwndbg.dbg_mod.Frame) -> pwndbg.dbg_mod.Value | None:
        regs = self.regs_in_frame(frame)
        value = regs.by_name(name)
        return value if value is not None else regs.by_name(name.upper())

    @pwndbg.aglib.proc.OnlyWhenQemuKernel
    @pwndbg.aglib.proc.OnlyWhenRunning
    def get_qemu_register(self, name: str) -> int | None:
        out = pwndbg.dbg.selected_inferior().send_monitor("info registers")
        match = re.search(rf"{name.split('_')[0]}=\s+([\da-fA-F]+)\s+([\da-fA-F]+)", out)

        if match:
            base = int(match.group(1), 16)
            limit = int(match.group(2), 16)

            if name.endswith("LIMIT"):
                return limit
            return base

        return None

    def read_reg_uncached_in_frame(
        self, reg: str, frame: pwndbg.dbg_mod.Frame, *aliases: str
    ) -> int | None:
        for name in (reg, *aliases):
            name = name.lstrip("$")
            try:
                value = self.get_register(name, frame)
                if value is None and name.lower() == "xpsr":
                    value = self.get_register("xPSR", frame)
                if value is None:
                    # Register not exposed by the debugger under this name;
                    # try the next alias, if any.
                    continue
                value = int(value)
                if name == "eip" and pwndbg.aglib.arch.name == "i8086":
                    cs = self.get_register("cs", frame)
                    if cs is None:
                        continue
                    value += int(cs) * 0x10

                # The value that the native debugger returns can be negative.
                # We convert this to the unsigned bit representation by masking it
                reg_definition = pwndbg.aglib.regs.current.reg_definitions.get(name.lower())
                if reg_definition and reg_definition.mask is not None:
                    mask = reg_definition.mask
                else:
                    mask = pwndbg.aglib.arch.ptrmask
                return int(value) & mask
            except (ValueError, pwndbg.dbg_mod.Error):
                continue
        return None

    def read_reg_uncached(self, reg: str, *aliases: str) -> int | None:
        frame = pwndbg.dbg.selected_frame()
        if frame is None:
            return None
        return self.read_reg_uncached_in_frame(reg, frame, *aliases)

    @pwndbg.lib.cache.cache_until("stop")
    def read_reg_in_frame(self, reg: str, frame: pwndbg.dbg_mod.Frame, *aliases: str) -> int | None:
        """
        Same as read_reg() except for the provided frame, rather than the currently
        selected frame.
        """
        return self.read_reg_uncached_in_frame(reg, frame, *aliases)

    def read_reg(self, reg: str, *aliases: str) -> int | None:
        """
        Query the underlying debugger for the value of a register.

        If `aliases` are provided, each is tried in turn after `reg` until one
        returns a non-None value. This is useful for architectural registers
        whose exposed names differ across debugger backends or QEMU versions
        (for example, newer QEMU exposes `vbar_el1` on AArch64 while older
        releases exposed it as `vbar`). Pass the most-likely-current name
        first; less-likely names last.

        Note that in some rare cases, debuggers won't directly expose the values of some special model specific registers.
        Although we can sometimes determine these by other indirect means, this function does not run any extra logic to handle these special cases.

        Specifically, if you need to ensure you are reading the correct value of "gs", "fs", "idt", or "idt_limit", use
        the specific helpers functions on the regs module as necessary to determine the values.

        Use read_reg_in_frame() if you have a `frame` object, its faster.
        """
        # Adding a cache_until decorator to read_reg() is semantically incorrect since it will return
        # the same register value even if the frame changes.
        frame = pwndbg.dbg.selected_frame()
        if frame is None:
            return None
        return self.read_reg_in_frame(reg, frame, *aliases)

    def write_reg(self, reg: str, value: int) -> None:
        if not pwndbg.dbg.selected_frame().reg_write(reg, value):
            raise RuntimeError(f"Attempted to write to a non-existent register '{reg}'")

    @property
    def pc(self) -> int | None:
        """Get the value of the program counter register"""
        return self.read_reg(self.current.pc)

    @pc.setter
    def pc(self, val: int) -> None:
        self.write_reg(self.current.pc, val)

    @property
    def sp(self) -> int | None:
        """Get the value of the stack pointer register"""
        return self.read_reg(self.current.stack)

    @sp.setter
    def sp(self, val: int) -> None:
        """Get the value of the stack pointer register"""
        self.write_reg(self.current.stack, val)

    def __contains__(self, reg: str) -> bool:
        return reg_sets[pwndbg.aglib.arch.name].__contains__(reg)

    def __iter__(self) -> Iterator[str]:
        return reg_sets[pwndbg.aglib.arch.name].__iter__()

    @property
    def current(self) -> RegisterSet:
        return reg_sets[pwndbg.aglib.arch.name]

    # TODO: All these should be able to do self.current
    @property
    def gpr(self) -> tuple[str, ...]:
        return reg_sets[pwndbg.aglib.arch.name].gpr

    @property
    def common(self) -> list[str]:
        return reg_sets[pwndbg.aglib.arch.name].common

    @property
    def frame(self) -> str | None:
        return reg_sets[pwndbg.aglib.arch.name].frame

    @property
    def retaddr(self) -> tuple[str, ...]:
        return reg_sets[pwndbg.aglib.arch.name].retaddr

    @property
    def kernel(self) -> KernelRegisterSet | None:
        return reg_sets[pwndbg.aglib.arch.name].kernel

    @property
    def flags(self) -> dict[str, BitFlags]:
        return reg_sets[pwndbg.aglib.arch.name].flags

    @property
    def extra_flags(self) -> dict[str, BitFlags]:
        return reg_sets[pwndbg.aglib.arch.name].extra_flags

    @property
    def stack(self) -> str:
        return reg_sets[pwndbg.aglib.arch.name].stack

    @property
    def retval(self) -> str | None:
        return reg_sets[pwndbg.aglib.arch.name].retval

    @property
    def all(self) -> set[str]:
        return reg_sets[pwndbg.aglib.arch.name].all

    def fix(self, expression: str) -> str:
        """
        This is used in CLI parsing.
        It takes in a string with a register name, "rax", and prefixes it with
        a $ ("$rax") so that the underlying debugger can evaluate it to resolve the value
        """
        expression = pwndbg.aglib.regs.current.resolve_aliases(expression)
        for regname in self.all:
            expression = re.sub(rf"\$?\b{regname}\b", r"$" + regname, expression)
        return expression

    def items(self) -> Generator[tuple[str, Any], None, None]:
        for regname in self.all:
            yield regname, self.read_reg(regname)

    reg_sets = reg_sets

    @property
    def changed(self) -> list[str]:
        delta: list[str] = []
        for reg, value in self.previous.items():
            if self.read_reg(reg) != value:
                delta.append(reg)
        return delta

    @property
    @pwndbg.aglib.proc.OnlyWhenQemuKernel
    @pwndbg.aglib.proc.OnlyWithArch(["i386", "x86-64"])
    @pwndbg.lib.cache.cache_until("stop")
    def idt(self) -> int | None:
        return self.get_qemu_register("IDT")

    @property
    @pwndbg.aglib.proc.OnlyWhenQemuKernel
    @pwndbg.aglib.proc.OnlyWithArch(["i386", "x86-64"])
    @pwndbg.lib.cache.cache_until("stop")
    def idt_limit(self) -> int | None:
        return self.get_qemu_register("IDT_LIMIT")

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def fsbase(self) -> int:
        return self._fs_gs_helper("fs_base", ARCH_GET_FS)

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def gsbase(self) -> int:
        return self._fs_gs_helper("gs_base", ARCH_GET_GS)

    def _fs_gs_helper(self, regname: str, which: int) -> int:
        """Supports fetching based on segmented addressing, a la fs:[0x30].
        Requires ptrace'ing the child directory if i386."""

        if pwndbg.aglib.arch.name == "x86-64":
            frame = pwndbg.dbg.selected_frame()
            if frame is None:
                return 0
            reg_value = self.get_register(regname, frame)
            return int(reg_value) if reg_value is not None else 0

        # We can't really do anything if the process is remote.
        if pwndbg.aglib.remote.is_remote():
            return 0

        # Use the lightweight process ID
        lwpid = pwndbg.dbg.selected_thread().ptid()

        # Get the register
        ppvoid = ctypes.POINTER(ctypes.c_void_p)
        value = ppvoid(ctypes.c_void_p())
        value.contents.value = 0

        libc = ctypes.CDLL("libc.so.6")
        result = libc.ptrace(PTRACE_ARCH_PRCTL, lwpid, value, which)

        if result == 0:
            return (value.contents.value or 0) & pwndbg.aglib.arch.ptrmask

        return 0


regs: RegisterManager = RegisterManager()


@pwndbg.dbg.event_handler(EventType.CONTINUE)
@pwndbg.dbg.event_handler(EventType.STOP)
def update_last() -> None:
    regs.previous = regs.last
    regs.last = {k: regs.read_reg(k) for k in regs.common}
    # TODO: Uncomment this once the LLDB command port PR for `context` is merged
    # if pwndbg.config.show_retaddr_reg:
    #    M.last.update({k: M[k] for k in M.retaddr})
