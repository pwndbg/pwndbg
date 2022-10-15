"""
Getting Thread Local Storage (TLS) information.
"""
import sys
from types import ModuleType

import gdb

import pwndbg.disasm
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.gdblib.vmmap


class module(ModuleType):
    """Getting Thread Local Storage (TLS) information."""

    _errno_offset = None

    def get_tls_base_via_errno_location(self) -> int:
        """Heuristically determine the base address of the TLS."""
        if pwndbg.gdblib.symbol.address(
            "__errno_location"
        ) is None or pwndbg.gdblib.arch.current not in (
            "x86-64",
            "i386",
            "arm",
        ):
            # Note: We doesn't implement this for aarch64 because its TPIDR_EL0 register seems always work
            # If oneday we can't get TLS base via TPIDR_EL0, we should implement this for aarch64
            return 0
        already_lock = gdb.parameter("scheduler-locking") == "on"
        old_config = gdb.parameter("scheduler-locking")
        if not already_lock:
            gdb.execute("set scheduler-locking on")
        errno_addr = int(gdb.parse_and_eval("(int *)__errno_location()"))
        if not already_lock:
            gdb.execute("set scheduler-locking %s" % old_config)

        if not self._errno_offset:
            __errno_location_instr = pwndbg.disasm.near(
                pwndbg.gdblib.symbol.address("__errno_location"), 5, show_prev_insns=False
            )
            if pwndbg.gdblib.arch.current == "x86-64":
                for instr in __errno_location_instr:
                    # Find something like: mov rax, qword ptr [rip + disp]
                    if instr.mnemonic == "mov":
                        self._errno_offset = pwndbg.gdblib.memory.s64(instr.next + instr.disp)
                        break
            elif pwndbg.gdblib.arch.current == "i386":
                for instr in __errno_location_instr:
                    # Find something like: mov eax, dword ptr [eax + disp]
                    # (disp is a negative value)
                    if instr.mnemonic == "mov":
                        # base offset is from the first `add eax` after `call __x86.get_pc_thunk.bx`
                        base_offset_instr = next(
                            instr for instr in __errno_location_instr if instr.mnemonic == "add"
                        )
                        base_offset = base_offset_instr.address + base_offset_instr.operands[1].int
                        self._errno_offset = pwndbg.gdblib.memory.s32(base_offset + instr.disp)
                        break
            elif pwndbg.gdblib.arch.current == "arm":
                ldr_instr = None
                for instr in __errno_location_instr:
                    if not ldr_instr and instr.mnemonic == "ldr":
                        ldr_instr = instr
                    elif ldr_instr and instr.mnemonic == "add":
                        offset = ldr_instr.operands[1].mem.disp
                        offset = pwndbg.gdblib.memory.s32((ldr_instr.address + 4 & -4) + offset)
                        self._errno_offset = pwndbg.gdblib.memory.s32(instr.address + 4 + offset)
                        break
        if not self._errno_offset:
            raise OSError("Can not find tls base")
        return errno_addr - self._errno_offset

    @property
    def address(self) -> int:
        """Get the base address of TLS."""
        if pwndbg.gdblib.arch.current not in ("x86-64", "i386", "aarch64", "arm"):
            # Not supported yet
            return 0

        tls_base = 0

        if pwndbg.gdblib.arch.current == "x86-64":
            tls_base = int(pwndbg.gdblib.regs.fsbase)
        elif pwndbg.gdblib.arch.current == "i386":
            tls_base = int(pwndbg.gdblib.regs.gsbase)
        elif pwndbg.gdblib.arch.current == "aarch64":
            tls_base = int(pwndbg.gdblib.regs.TPIDR_EL0)

        # Sometimes, we need to get TLS base via errno location for the following reason:
        # For x86-64, fsbase might be 0 if we are remotely debugging and the GDB version <= 8.X
        # For i386, gsbase might be 0 if we are remotely debugging
        # For arm (32-bit), we doesn't have other choice
        # Note: aarch64 seems doesn't have this issue
        is_valid_tls_base = (
            pwndbg.gdblib.vmmap.find(tls_base) is not None
            and tls_base % pwndbg.gdblib.arch.ptrsize == 0
        )
        return tls_base if is_valid_tls_base else self.get_tls_base_via_errno_location()


@pwndbg.gdblib.events.exit
def reset():
    # We should reset the offset when we attach to a new process or something
    pwndbg.gdblib.tls._errno_offset = None


# To prevent garbage collection
tether = sys.modules[__name__]
sys.modules[__name__] = module(__name__, "")
