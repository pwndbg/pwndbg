"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""
import ctypes
import re
import sys
from types import ModuleType
from typing import Dict

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.proc
import pwndbg.gdblib.remote
import pwndbg.lib.memoize
from pwndbg.lib.regs import reg_sets


@pwndbg.gdblib.proc.OnlyWhenRunning
def gdb77_get_register(name):
    return gdb.parse_and_eval("$" + name)


@pwndbg.gdblib.proc.OnlyWhenRunning
def gdb79_get_register(name):
    return gdb.selected_frame().read_register(name)


try:
    gdb.Frame.read_register
    get_register = gdb79_get_register
except AttributeError:
    get_register = gdb77_get_register


# We need to manually make some ptrace calls to get fs/gs bases on Intel
PTRACE_ARCH_PRCTL = 30
ARCH_GET_FS = 0x1003
ARCH_GET_GS = 0x1004


class module(ModuleType):
    last: Dict[str, int] = {}

    @pwndbg.lib.memoize.reset_on_stop
    @pwndbg.lib.memoize.reset_on_prompt
    def __getattr__(self, attr):
        attr = attr.lstrip("$")
        try:
            # Seriously, gdb? Only accepts uint32.
            if "eflags" in attr or "cpsr" in attr:
                value = gdb77_get_register(attr)
                value = value.cast(pwndbg.gdblib.typeinfo.uint32)
            else:
                value = get_register(attr)
                if value is None and attr.lower() == "xpsr":
                    value = get_register("xPSR")
                size = pwndbg.gdblib.typeinfo.unsigned.get(
                    value.type.sizeof, pwndbg.gdblib.typeinfo.ulong
                )
                value = value.cast(size)
                if attr.lower() == "pc" and pwndbg.gdblib.arch.current == "i8086":
                    value += self.cs * 16

            value = int(value)
            return value & pwndbg.gdblib.arch.ptrmask
        except (ValueError, gdb.error):
            return None

    def __setattr__(self, attr, val):
        if attr == "last" or attr == "previous":
            return super().__setattr__(attr, val)
        else:
            # Not catching potential gdb.error as this should never
            # be called in a case when this can throw
            gdb.execute(f"set ${attr} = {val}")

    @pwndbg.lib.memoize.reset_on_stop
    @pwndbg.lib.memoize.reset_on_prompt
    def __getitem__(self, item):
        if not isinstance(item, str):
            print("Unknown register type: %r" % (item))
            return None

        # e.g. if we're looking for register "$rax", turn it into "rax"
        item = item.lstrip("$")
        item = getattr(self, item.lower())

        if isinstance(item, int):
            return int(item) & pwndbg.gdblib.arch.ptrmask

        return item

    def __iter__(self):
        regs = set(reg_sets[pwndbg.gdblib.arch.current]) | {"pc", "sp"}
        for item in regs:
            yield item

    @property
    def current(self):
        return reg_sets[pwndbg.gdblib.arch.current]

    # TODO: All these should be able to do self.current
    @property
    def gpr(self):
        return reg_sets[pwndbg.gdblib.arch.current].gpr

    @property
    def common(self):
        return reg_sets[pwndbg.gdblib.arch.current].common

    @property
    def frame(self):
        return reg_sets[pwndbg.gdblib.arch.current].frame

    @property
    def retaddr(self):
        return reg_sets[pwndbg.gdblib.arch.current].retaddr

    @property
    def flags(self):
        return reg_sets[pwndbg.gdblib.arch.current].flags

    @property
    def stack(self):
        return reg_sets[pwndbg.gdblib.arch.current].stack

    @property
    def retval(self):
        return reg_sets[pwndbg.gdblib.arch.current].retval

    @property
    def all(self):
        regs = reg_sets[pwndbg.gdblib.arch.current]
        retval = []
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
            elif isinstance(regset, (list, tuple)):
                retval.extend(regset)
            elif isinstance(regset, dict):
                retval.extend(regset.keys())
            else:
                retval.append(regset)
        return retval

    def fix(self, expression):
        for regname in set(self.all + ["sp", "pc"]):
            expression = re.sub(r"\$?\b%s\b" % regname, r"$" + regname, expression)
        return expression

    def items(self):
        for regname in self.all:
            yield regname, self[regname]

    reg_sets = reg_sets

    @property
    def changed(self):
        delta = []
        for reg, value in self.previous.items():
            if self[reg] != value:
                delta.append(reg)
        return delta

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def fsbase(self):
        return self._fs_gs_helper("fs_base", ARCH_GET_FS)

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def gsbase(self):
        return self._fs_gs_helper("gs_base", ARCH_GET_GS)

    @pwndbg.lib.memoize.reset_on_stop
    def _fs_gs_helper(self, regname, which):
        """Supports fetching based on segmented addressing, a la fs:[0x30].
        Requires ptrace'ing the child directly for GDB < 8."""

        # For GDB >= 8.x we can use get_register directly
        # Elsewhere we have to get the register via ptrace
        if get_register == gdb79_get_register:
            return get_register(regname)

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

    def __repr__(self):
        return "<module pwndbg.gdblib.regs>"


# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, "")


@pwndbg.gdblib.events.cont
@pwndbg.gdblib.events.stop
def update_last():
    M = sys.modules[__name__]
    M.previous = M.last
    M.last = {k: M[k] for k in M.common}
    if pwndbg.gdblib.config.show_retaddr_reg:
        M.last.update({k: M[k] for k in M.retaddr})
