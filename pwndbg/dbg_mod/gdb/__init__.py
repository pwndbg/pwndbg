from __future__ import annotations

import re
from asyncio import CancelledError
from collections.abc import Callable
from collections.abc import Coroutine
from collections.abc import Generator
from collections.abc import Iterator
from collections.abc import Sequence
from contextlib import contextmanager
from contextlib import nullcontext
from contextlib import suppress
from os import environ
from pathlib import Path
from random import randint
from typing import Any
from typing import Literal
from typing import TypeVar

import gdb
import gdb.types
from typing_extensions import override

import pwndbg
import pwndbg.aglib.remote
import pwndbg.dbg_mod
import pwndbg.gdblib
import pwndbg.gdblib.events
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.lib.path
from pwndbg.color import message
from pwndbg.dbg_mod import EventHandlerPriority
from pwndbg.dbg_mod import EventType
from pwndbg.dbg_mod import selection
from pwndbg.gdblib import load_gdblib
from pwndbg.lib.arch import ArchAttribute
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform
from pwndbg.lib.siginfo import SigInfo
from pwndbg.lib.siginfo import SigInfoKill
from pwndbg.lib.siginfo import SigInfoRt
from pwndbg.lib.siginfo import SigInfoSigChld
from pwndbg.lib.siginfo import SigInfoSigFault
from pwndbg.lib.siginfo import SigInfoSigPoll
from pwndbg.lib.siginfo import SigInfoSigSys
from pwndbg.lib.siginfo import SigInfoSigVal
from pwndbg.lib.siginfo import SigInfoTimer

T = TypeVar("T")


# List of supported architectures that GDB recognizes
# These strings to converted to the Pwndbg-specific name for the architecture
gdb_architecture_name_fixup_list = (
    "x86-64",
    "i386",
    "i8086",
    "aarch64",
    "mips",
    "rs6000",
    "powerpc",
    "sparc",
    "arm",
    "iwmmxt",
    "iwmmxt2",
    "xscale",
    "riscv:rv32",
    "riscv:rv64",
    "riscv",
    "loongarch64",
    "s390:64-bit",
)

# `show architecture` returns a string like "mips:isa32r5"
gdb_mips_to_arch_attribute_map = {
    "mips5": ArchAttribute.MIPS_ISA_5,
    "micromips": ArchAttribute.MIPS_ISA_MICRO,
    "isa32": ArchAttribute.MIPS_ISA_32,
    "isa32r2": ArchAttribute.MIPS_ISA_32R2,
    "isa32r3": ArchAttribute.MIPS_ISA_32R3,
    "isa32r5": ArchAttribute.MIPS_ISA_32R5,
    "isa32r6": ArchAttribute.MIPS_ISA_32R6,
    "isa64": ArchAttribute.MIPS_ISA_64,
    "isa64r2": ArchAttribute.MIPS_ISA_64R2,
    "gs264e": ArchAttribute.MIPS_ISA_64R2,
    "gs464": ArchAttribute.MIPS_ISA_64R2,
    "gs464e": ArchAttribute.MIPS_ISA_64R2,
    "isa64r3": ArchAttribute.MIPS_ISA_64R3,
    "isa64r5": ArchAttribute.MIPS_ISA_64R5,
    "isa64r6": ArchAttribute.MIPS_ISA_64R6,
}


def parse_and_eval(expression: str, global_context: bool) -> gdb.Value:
    """
    Same as `gdb.parse_and_eval`, but only uses `global_context` if it is
    supported by the current version of GDB.

    `global_context` was introduced in GDB 14.
    """
    try:
        return gdb.parse_and_eval(expression, global_context)
    except TypeError:
        return gdb.parse_and_eval(expression)


def _get_frame_stack_variables(frame: gdb.Frame) -> tuple[tuple[int, int, str], ...]:
    try:
        block = frame.block()
    except (gdb.error, RuntimeError):
        # gdb.error: No frame selected (no active inferior)
        # RuntimeError: Frame exists and selected,
        # But no DWARF info, such as in the case of stripped binaries
        return ()

    if not block:
        return ()

    variables = []
    while block:
        for sym in block:
            if not (sym.is_variable or sym.is_argument):
                continue

            try:
                value = sym.value(frame)
                # value.address can be None
                # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Values-From-Inferior.html#Values-From-Inferior:~:text=Variable%3A%20Value%2Eaddress
                # https://sourceware.org/bugzilla/show_bug.cgi?id=33860
                if value.address is None:
                    continue

                addr = int(value.address)
                size = value.type.sizeof
                variables.append((addr, addr + size, sym.name))
            except (gdb.error, AttributeError):
                # FIXME: We should get rid of this try-except in favour of checking the necessary conditions beforehand.
                continue

        block = block.superblock

    return tuple(variables)


class GDBRegisters(pwndbg.dbg_mod.Registers):
    def __init__(self, frame: GDBFrame):
        self.frame = frame

    @override
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        try:
            return GDBValue(self.frame.inner.read_register(name))
        except (gdb.error, ValueError):
            # GDB throws an exception if the name is unknown, we just return
            # None when that is the case.
            pass
        return None


class GDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: gdb.Frame):
        self.inner = inner
        # caching the hash since calculating it involves some string operations
        self._hash: int | None = None

    @override
    def lookup_symbol(
        self,
        name: str,
        *,
        type: pwndbg.dbg_mod.SymbolLookupType = pwndbg.dbg_mod.SymbolLookupType.ANY,
    ) -> pwndbg.dbg_mod.Value | None:
        from pwndbg.dbg_mod.gdb.symbol import Domain
        from pwndbg.dbg_mod.gdb.symbol import lookup_frame_symbol

        domain = {
            pwndbg.dbg_mod.SymbolLookupType.ANY: Domain.ANY,
            pwndbg.dbg_mod.SymbolLookupType.VARIABLE: Domain.VARIABLE,
            pwndbg.dbg_mod.SymbolLookupType.FUNCTION: Domain.FUNCTION,
        }[type]
        try:
            if (val := lookup_frame_symbol(name, domain=domain)) is not None:
                return GDBValue(val)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)
        return None

    @override
    def evaluate_expression(
        self, expression: str, lock_scheduler: bool = False
    ) -> pwndbg.dbg_mod.Value:
        from pwndbg.gdblib.scheduler import lock_scheduler as do_lock_scheduler

        with do_lock_scheduler() if lock_scheduler else nullcontext():
            with selection(self.inner, lambda: gdb.selected_frame(), lambda f: f.select()):
                try:
                    value = parse_and_eval(expression, global_context=False)
                except gdb.error as e:
                    raise pwndbg.dbg_mod.Error(e)

        return GDBValue(value)

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return GDBRegisters(self)

    @override
    def reg_write(self, name: str, val: int) -> bool:
        import pwndbg.aglib

        if name not in pwndbg.aglib.regs:
            return False

        with selection(self.inner, lambda: gdb.selected_frame(), lambda f: f.select()):
            try:
                gdb.execute(f"set ${name} = {val}")
                return True
            except gdb.error as e:
                raise pwndbg.dbg_mod.Error(e)

    @override
    def pc(self) -> int:
        return int(self.inner.pc())

    @override
    def sp(self) -> int:
        # I don't see this exposed anywhere in the API nor in `info frame`, so we will have
        # to read from the inferior. `sp` is resolved by GDB to the architecture-specific stack pointer.
        return int(self.regs().by_name("sp"))

    @override
    def start(self) -> int | None:
        # How is it possible that this isn't in the API?
        # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Frames-In-Python.html#Frames-In-Python
        import pwndbg.aglib

        # We're gonna parse this:
        # e.g. `str(self.inner) == "{stack=0x7fffffffe030,code=0x00007ffff7fe0880,!special}"`
        # See gdb/python/py-frame.c:frapy_str() and gdb/frame.c:frame_id::to_string()
        # They really could just expose .stack() as an API...
        # We could have also chosen to parse `gdb.execute("info frame")`.

        str_id = str(self.inner)
        if "stack=0x" in str_id:
            # GDB for some reason returns one ptr past retaddr
            return (
                int(str_id.partition("stack=")[2].partition(",")[0], 16) - pwndbg.aglib.arch.ptrsize
            )
        # We got "!stack", "stack=<unavailable>", "stack=<sentinel>" or "stack=<outer>".
        return None

    @override
    def parent(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            parent = self.inner.older()
            if parent is not None:
                return GDBFrame(parent)
        except (gdb.error, gdb.MemoryError) as e:
            # We can encounter a `gdb.error: PC not saved` here.
            raise pwndbg.dbg_mod.Error(e)

        return None

    @override
    def child(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            child = self.inner.newer()
            if child is not None:
                return GDBFrame(child)
        except (gdb.error, gdb.MemoryError) as e:
            # We can encounter a `gdb.error: PC not saved` here.
            raise pwndbg.dbg_mod.Error(e)

        return None

    @override
    def sal(self) -> tuple[str, int] | None:
        sal = self.inner.find_sal()  # gdb.Symtab_and_line
        if sal.symtab is None:
            return None

        return sal.symtab.fullname(), sal.line

    @override
    @pwndbg.lib.cache.cache_until("forever")
    def stack_variables(self) -> tuple[tuple[int, int, str], ...]:
        import pwndbg.aglib.qemu

        if pwndbg.aglib.qemu.is_qemu_kernel():
            # Workaround for GDB bug:
            # https://sourceware.org/bugzilla/show_bug.cgi?id=33861
            # https://github.com/pwndbg/pwndbg/issues/3693
            # Unfortunately there is no consistent way to detect this, I've had it
            # happen even on block0 with hex(block.end - block.start) == 0x14a,
            # so we simply don't support getting stack variables on GDB when kernel
            # debugging.
            return ()
        return _get_frame_stack_variables(self.inner)

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, GDBFrame), "tried to compare GDBFrame to other type"
        other: GDBFrame = rhs

        return self.inner == other.inner

    @override
    def idx(self) -> int:
        # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Frames-In-Python.html#Frames-In-Python:~:text=Frame%2Elevel
        return self.inner.level()

    def _frame_id(self) -> tuple[int, int, int, int]:
        """
        Returns a tuple which recovers the frame_id struct of the GDB frame object (self.inner).
        We cannot recover only frame_id.user_created_p.

        Format is (stack_addr, code_addr, special_addr, artificial_depth).

        The status fields are returned implicitly in the following:
            stack_addr == -1 means stack_status == FID_STACK_INVALID
            stack_addr == -2 means stack_status == FID_STACK_UNAVAILABLE
            stack_addr == -3 means stack_status == FID_STACK_SENTINEL
            stack_addr == -4 means stack_status == FID_STACK_OUTER
            code_addr == -1 means code_addr_p == 0
            special_addr == -1 means special_addr_p == 0
        Note that artificial_depth == 0 means invalid.
        Note that stack_addr is the start of the stack, not the value of the stack pointer.
        """
        # See gdb/frame-id.h and gdb/frame.c:frame_id::to_string().
        # This obviously isn't guaranteed to be stable, but looking at the blame
        # of to_string() it has been.

        # Here is an example of what is can look like:
        # "{stack=0x7fffffffe030,code=0x00007ffff7fe0880,!special}"
        frame_id_str: str = str(self.inner)

        # Get rid of curly braces and split into individual fields.
        splitted: list[str] = frame_id_str[1:-1].split(",")

        stack_addr: int
        code_addr: int
        special_addr: int
        artificial_addr: int

        match splitted[0]:
            case "!stack":
                stack_addr = -1
            case "stack=<unavailable>":
                stack_addr = -2
            case "stack=<sentinel>":
                stack_addr = -3
            case "stack=<outer>":
                stack_addr = -4
            case _:
                # We have an actual address (len("stack=") == 6)
                stack_addr = int(splitted[0][6:], 16)

        if splitted[1] == "!code":
            code_addr = -1
        else:
            # len("code=") == 5
            code_addr = int(splitted[1][5:], 16)

        if splitted[2] == "!special":
            special_addr = -1
        else:
            # len("special=") == 8
            special_addr = int(splitted[2][8:], 16)

        if len(splitted) == 3:
            artificial_addr = -1
        else:
            # len("artificial=") == 11
            artificial_addr = int(splitted[3][11:], 16)

        return (stack_addr, code_addr, special_addr, artificial_addr)

    @override
    def __hash__(self) -> int:
        if self._hash is not None:
            # The object is immutable, so this works.
            return self._hash

        # GDB implements the equality comparison in gdb/python/py-frame.c:frapy_richcompare()
        # and gdb/frame.c:frame_id::operator==().
        # The frame_id is not exposed to the python API, but we can exploit str(self.inner)
        # to recover it. (though still don't have frame_id_is_next, but oh well..)
        # This is much faster than reading the stack pointer from the inferior, and will give
        # more accurate results as well.
        stack_addr, code_addr, special_addr, artificial_depth = self._frame_id()
        # stack_addr == -1 (FID_STACK_INVALID) acts as NaN, so we have to be unique
        if stack_addr == -1:
            self._hash = randint(0, 1 << 63)
            return self._hash

        # I don't want to make assumptions on the sizes of all these fields so I will just build up a
        # string and use the string's hash. Using "|" for domain separation.
        self._hash = hash(
            f"{stack_addr}|{code_addr}|{special_addr}|{artificial_depth}|"
            # Still using idx() for good measure (maybe it helps with the lack of frame_id_is_next?)
            # Still using number_of_stops_since_birth because I want to guarantee that same frames at
            # different times return different hashes.
            f"{self.idx()}|{pwndbg.dbg_mod.number_of_stops_since_birth}"
        )

        return self._hash


class GDBThread(pwndbg.dbg_mod.Thread):
    def __init__(self, inner: gdb.InferiorThread):
        self.inner = inner

    @override
    @contextmanager
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        with selection(self.inner, lambda: gdb.selected_thread(), lambda t: t.switch()):
            yield GDBFrame(gdb.newest_frame())

    @override
    def ptid(self) -> int | None:
        _, lwpid, _ = self.inner.ptid
        return lwpid

    @override
    def index(self) -> int:
        return self.inner.num

    @override
    def siginfo(self) -> SigInfo | None:
        try:
            gdb_siginfo_expr = pwndbg.dbg.selected_inferior().evaluate_expression("$_siginfo")
            siginfo = SigInfo(
                si_signo=int(gdb_siginfo_expr["si_signo"]),
                si_errno=int(gdb_siginfo_expr["si_errno"]),
                si_code=int(gdb_siginfo_expr["si_code"]),
                kill=SigInfoKill(
                    si_pid=int(gdb_siginfo_expr["_sifields"]["_kill"]["si_pid"]),
                    si_uid=int(gdb_siginfo_expr["_sifields"]["_kill"]["si_uid"]),
                ),
                timer=SigInfoTimer(
                    si_tid=int(gdb_siginfo_expr["_sifields"]["_timer"]["si_tid"]),
                    si_overrun=int(gdb_siginfo_expr["_sifields"]["_timer"]["si_overrun"]),
                    si_sigval=SigInfoSigVal(
                        sival_int=int(
                            gdb_siginfo_expr["_sifields"]["_timer"]["si_sigval"]["sival_int"]
                        ),
                        sival_ptr=int(
                            gdb_siginfo_expr["_sifields"]["_timer"]["si_sigval"]["sival_ptr"]
                        ),
                    ),
                ),
                rt=SigInfoRt(
                    si_pid=int(gdb_siginfo_expr["_sifields"]["_rt"]["si_pid"]),
                    si_uid=int(gdb_siginfo_expr["_sifields"]["_rt"]["si_uid"]),
                    si_sigval=SigInfoSigVal(
                        sival_int=int(
                            gdb_siginfo_expr["_sifields"]["_rt"]["si_sigval"]["sival_int"]
                        ),
                        sival_ptr=int(
                            gdb_siginfo_expr["_sifields"]["_rt"]["si_sigval"]["sival_ptr"]
                        ),
                    ),
                ),
                sigchld=SigInfoSigChld(
                    si_pid=int(gdb_siginfo_expr["_sifields"]["_sigchld"]["si_pid"]),
                    si_uid=int(gdb_siginfo_expr["_sifields"]["_sigchld"]["si_uid"]),
                    si_status=int(gdb_siginfo_expr["_sifields"]["_sigchld"]["si_status"]),
                    si_utime=int(gdb_siginfo_expr["_sifields"]["_sigchld"]["si_utime"]),
                    si_stime=int(gdb_siginfo_expr["_sifields"]["_sigchld"]["si_stime"]),
                ),
                sigfault=SigInfoSigFault(
                    si_addr=int(gdb_siginfo_expr["_sifields"]["_sigfault"]["si_addr"]),
                ),
                sigpoll=SigInfoSigPoll(
                    si_band=int(gdb_siginfo_expr["_sifields"]["_sigpoll"]["si_band"]),
                    si_fd=int(gdb_siginfo_expr["_sifields"]["_sigpoll"]["si_fd"]),
                ),
                sigsys=SigInfoSigSys(
                    call_addr=int(gdb_siginfo_expr["_sifields"]["_sigsys"]["_call_addr"]),
                    syscall=int(gdb_siginfo_expr["_sifields"]["_sigsys"]["_syscall"]),
                    arch=int(gdb_siginfo_expr["_sifields"]["_sigsys"]["_arch"]),
                ),
            )
            return siginfo
        except pwndbg.dbg_mod.Error:
            return None


class GDBMemoryMap(pwndbg.dbg_mod.MemoryMap):
    def __init__(self, qemu: bool, pages: Sequence[pwndbg.lib.memory.Page]):
        super().__init__(pages)
        self.qemu = qemu

    @override
    def is_qemu(self) -> bool:
        return self.qemu


# While this implementation allows breakpoints to be deleted, enabled and
# disabled from inside the code in a stop handler, GDB does not[1]. Aditionally,
# it behaves largely unpredictably when we try to do it. So, in order to allow
# for these things, we defer the operations on the GDB side until we're sure
# we can do them, and do some extra work on the Pwndbg side.
#
# [1]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html#Breakpoints-In-Python
BPWP_DEFERRED_DELETE: set[GDBStopPoint] = set()
BPWP_DEFERRED_ENABLE: set[GDBStopPoint] = set()
BPWP_DEFERRED_DISABLE: set[GDBStopPoint] = set()
# See pwndbg/dbg_mod/gdb/hooks.py !


class BreakpointAdapter(gdb.Breakpoint):
    stop_handler: Callable[[], bool]

    @override
    def stop(self) -> bool:
        return self.stop_handler()


class FinishpointAdapter(gdb.FinishBreakpoint):
    stop_handler: Callable[[], bool]

    def __init__(self, stop_handler, internal):
        super().__init__(gdb.newest_frame(), internal)
        self.stop_handler = stop_handler

    @override
    def stop(self) -> bool:
        result = self.stop_handler()
        return result


class GDBStopPoint(pwndbg.dbg_mod.StopPoint):
    inner: gdb.Breakpoint
    proc: GDBProcess
    inner_stop: Callable[[], bool] | None

    def __init__(self, inner: gdb.Breakpoint, proc: GDBProcess):
        self.inner = inner
        self.proc = proc
        self.inner_stop = None

    def _stop(self):
        """
        This function implements the same protocol as the GDB stop() function
        and may be slotted in place of the original function in case we need to
        disable or delete a breakpoint or watchpoint during the handling of
        a stop function.
        """
        if self not in BPWP_DEFERRED_DISABLE and self not in BPWP_DEFERRED_DELETE:
            return self.inner_stop()
        return False

    def _clear(self):
        """
        Removes the soft-disable aware handler and restores the original handler,
        if one was installed.
        """
        if self.inner_stop is not None:
            self.inner.stop = self.inner_stop
            self.inner_stop = None

    @override
    def set_enabled(self, enabled: bool) -> None:
        if self.proc.in_bpwp_stop_handler:
            # We're doing this during a stop handle. Change the stop function
            # in the breakpoint for the version that supports soft-disabling of
            # the breakpoint and then soft-disable it.
            self.inner_stop = self.inner.stop
            self.inner.stop = self._stop

            if enabled:
                target = BPWP_DEFERRED_ENABLE
                other = BPWP_DEFERRED_DISABLE
            else:
                target = BPWP_DEFERRED_DISABLE
                other = BPWP_DEFERRED_ENABLE
            if self in other:
                other.remove(self)

            target.add(self)
        else:
            # We're not in the middle of a stop handle, just enable or disable
            # it directly in GDB.
            self.inner.enabled = enabled

    @override
    def remove(self) -> None:
        if self.proc.in_bpwp_stop_handler:
            # Same as in `set_enabled`. We can't actually disable it right away,
            # but we can stop the handle from running and prevent the breakpoint
            # from stopping the program until it actually gets deleted.
            self.inner_stop = self.inner.stop
            self.inner.stop = self._stop
            BPWP_DEFERRED_DELETE.add(self)
        else:
            self.inner.delete()


class GDBProcess(pwndbg.dbg_mod.Process):
    # Operations that change the internal state of GDB are generally not allowed
    # during breakpoint stop handles. Because the Pwndbg Debugger-agnostic API
    # generally does not have this limitation, we keep track of these handles,
    # in order to properly block off or implement operations we support, but
    # that GDB would misbehave doing.
    in_bpwp_stop_handler: bool

    def __init__(self, inner: gdb.Inferior):
        self.inner = inner
        self.in_bpwp_stop_handler = False

    @override
    def threads(self) -> list[pwndbg.dbg_mod.Thread]:
        return [GDBThread(thread) for thread in gdb.selected_inferior().threads()]

    @override
    def pid(self) -> int | None:
        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return None

    @override
    def alive(self) -> bool:
        return gdb.selected_thread() is not None

    @override
    def is_core_file(self) -> bool:
        inferior = gdb.selected_inferior()
        return (
            hasattr(inferior, "connection")
            and inferior.connection is not None
            and inferior.connection.type == "core"
        )

    @override
    def stopped_with_signal(self) -> bool:
        # FIXME: `info program` is hacky (#3976)
        return "It stopped with signal " in gdb.execute("info program", to_string=True)

    @override
    def stopped_at_breakpoint(self) -> bool:
        # FIXME: `info program` is hacky (#3976)
        gdb_prog: str = gdb.execute("info program", to_string=True)
        # The first happens when e.g. running start
        # ("It stopped at a breakpoint that has since been deleted.")
        # the second on actual user set breakpoints
        # ("It stopped at breakpoint 2.")
        return "It stopped at a breakpoint " in gdb_prog or "It stopped at breakpoint " in gdb_prog

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(parse_and_eval(expression, global_context=True))
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def vmmap(self) -> pwndbg.dbg_mod.MemoryMap:
        import pwndbg.aglib.qemu
        from pwndbg.aglib.kernel.vmmap import kernel_vmmap
        from pwndbg.aglib.vmmap_custom import get_custom_pages
        from pwndbg.gdblib.vmmap import get_known_maps

        qemu = pwndbg.aglib.qemu.is_old_qemu_user()
        proc_maps = get_known_maps()
        # The `proc_maps` is usually a tuple of Page objects but it can also be:
        #   None    - when /proc/$tid/maps does not exist/is not available
        #   tuple() - when the process has no maps yet which happens only during its very early init
        #             (usually when we attach to a process)
        if proc_maps is not None:
            return GDBMemoryMap(qemu, proc_maps)

        pages: list[pwndbg.lib.memory.Page] = []
        pages.extend(kernel_vmmap())
        pages.extend(get_custom_pages())
        pages.sort()
        return GDBMemoryMap(qemu, pages)

    def _is_memory_readable(self, addr: int) -> bool:
        try:
            gdb.selected_inferior().read_memory(addr, 1)
            return True
        except gdb.error:
            return False

    def _find_memory_last_readable(self, start: int, count: int) -> int:
        end = start + count
        result = -1

        if not self._is_memory_readable(start):
            return result

        while start <= end:
            mid = (start + end + 1) // 2
            if self._is_memory_readable(mid):
                result = mid
                start = mid + 1
            else:
                end = mid - 1

        return result

    @override
    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        count = max(int(size), 0)
        addr = address

        try:
            result = gdb.selected_inferior().read_memory(addr, count)
            return bytearray(result)
        except gdb.error as e:
            if not partial:
                raise pwndbg.dbg_mod.Error(e)

            if not pwndbg.aglib.remote.is_remote():
                message = str(e)
                match = re.search(r"Memory at address (\w+) unavailable\.", message)
                if match:
                    stop_addr = int(match.group(1), 0)
                else:
                    stop_addr = int(message.split()[-1], 0)

                # Handle case of memory read that wraps around the memory space back to 0, where high memory was readable but memory at 0 was not.
                # Example: 2-byte read at 0xFFFF_FFFF in a 32-bit address space.
                # GDB returns error: "Cannot access memory at address 0x0"
                if stop_addr == 0 and stop_addr < addr:
                    # We could read from the top-portion of memory, but not after wrapping around
                    # Because we are doing a partial read, read until the max address
                    return self.read_memory(addr, pwndbg.aglib.arch.ptrmask - addr + 1)

                if stop_addr > addr:
                    return self.read_memory(addr, stop_addr - addr)
            # Handle the case of remote debugging, where GDB's remote protocol
            # returns the start address as the failed read address instead of the stop address.
            # This is a limitation in how GDB handles the remote protocol, and while it could
            # be fixed, it currently behaves this way.
            #
            # To work around this, we perform a binary search in the `_find_memory_last_readable` method
            # to find the correct stop address that avoids the failure.
            #
            # For local debugging, this issue does not occur, and we proceed with the normal flow.
            elif (stop_addr := self._find_memory_last_readable(addr, count)) > 0:
                return self.read_memory(addr, stop_addr - addr + 1)

            raise pwndbg.dbg_mod.Error(e)

    @override
    def write_memory(self, address: int, data: bytearray, partial: bool = False) -> int:
        try:
            # Throws an exception if can't access memory
            gdb.selected_inferior().write_memory(address, data)
        except gdb.MemoryError as e:
            if partial:
                raise NotImplementedError("partial writes are currently not supported under gdb")

            raise pwndbg.dbg_mod.Error(e)
        return len(data)

    @override
    def find_in_memory(
        self,
        pattern: bytearray,
        start: int,
        size: int,
        align: int,
        max_matches: int = -1,
        step: int = -1,
    ) -> Generator[int, None, None]:
        if max_matches == 0 or len(pattern) == 0:
            # Nothing to match.
            return

        i = gdb.selected_inferior()
        end = start + size
        limit = None if max_matches < 0 else max_matches
        found_count = 0

        while True:
            # No point in searching if we can't read the memory
            try:
                i.read_memory(start, 1)
            except gdb.MemoryError:
                break

            length = end - start
            if length <= 0:
                break

            try:
                start = i.search_memory(start, length, pattern)
            except gdb.error as e:
                # While remote debugging on an embedded device and searching
                # through a large memory region (~512mb), gdb may return an error similar
                # to `error: Invalid hex digit 116`, even though the search
                # itself is ok. It seems to have to do with a timeout.
                print(f"WARN: gdb.search_memory failed with: {e}")
                if e.args[0].startswith("Invalid hex digit"):
                    print(
                        "WARN: This is possibly related to a timeout. Connection is likely broken."
                    )
                    break
                start = None

            if start is None:
                break

            # Fix bug: In kernel mode, search_memory may return a negative address,
            # e.g. -1073733344, which supposed to be 0xffffffffc0002120 in kernel.
            start &= 0xFFFFFFFFFFFFFFFF

            # Ignore results that don't match required alignment
            if start & (align - 1):
                start = pwndbg.lib.memory.round_up(start, align)
                continue

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            try:
                i.read_memory(start, 1)
            except gdb.MemoryError:
                break

            yield start
            found_count += 1
            if limit and found_count >= limit:
                break

            if step > 0:
                start = pwndbg.lib.memory.round_down(start, step) + step
            elif align > 1:
                start = pwndbg.lib.memory.round_up(start + len(pattern), align)
            else:
                start += len(pattern)

    @override
    def is_remote(self) -> bool:
        # Example:
        # pwndbg> maintenance print target-stack
        # The current target stack is:
        #   - remote (Remote serial target in gdb-specific protocol)
        #   - exec (Local exec file)
        #   - None (None)
        return "remote" in gdb.execute("maintenance print target-stack", to_string=True)

    @override
    def send_remote(self, packet: str) -> bytes:
        conn = self.inner.connection
        assert isinstance(conn, gdb.RemoteTargetConnection), (
            "Called send_remote() on a local process"
        )
        assert conn.is_valid(), "connection is invalid"

        # NOTE: `send_packet` don't handle reading multiple responses
        try:
            return conn.send_packet(packet) or b""
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def send_monitor(self, cmd: str) -> str:
        try:
            return gdb.execute(f"monitor {cmd}", to_string=True)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def download_remote_file(self, remote_path: str, local_path: str) -> None:
        import pwndbg.aglib.file

        if pwndbg.aglib.file.is_vfile_qemu_user_bug():
            with open(local_path, "wb") as fp:
                try:
                    fp.writelines(pwndbg.aglib.file.vfile_readfile(remote_path))
                    return
                except OSError as e:
                    raise pwndbg.dbg_mod.Error(
                        f"Could not download remote file {remote_path!r}:\nError: {str(e)}"
                    )
        try:
            error = gdb.execute(f'remote get "{remote_path}" "{local_path}"', to_string=True)
        except gdb.error as e:
            error = str(e)

        if error:
            # If the client is configured with set debug remote 1, we need to
            # skip [remote] lines, and not interpret as missing file. Maybe
            # better to search for error strings. A real error will say:
            # "Remote I/O error: No such file or directory"
            real_error = []
            for line in error.splitlines():
                if not line.startswith("[remote]"):
                    real_error.append(line)
            if len(real_error):
                error = "\n".join(real_error)
                raise pwndbg.dbg_mod.Error(
                    f"Could not download remote file {remote_path!r}:\nError: {error}"
                )

    # Note that in GDB this method does not depend on the process at all!
    #
    # From the point-of-view of the GDB implementation, this could very well be
    # implemented as part of Debugger. The issue with that, however, is that the
    # LLDB implementation would have to do some fairly heavy legwork to keep up
    # the appearance that values are independent from any given target.
    #
    # Opting instead to have this method be at this level, although slightly
    # redundant in GDB, saves a ton of work in LLDB.
    @override
    def create_value(
        self, value: int, type: pwndbg.dbg_mod.Type | None = None
    ) -> pwndbg.dbg_mod.Value:
        v = GDBValue(gdb.Value(value))
        if type:
            v = v.cast(type)

        return v

    @override
    def symbol_name_at_address(self, address: int) -> str | None:
        from pwndbg.dbg_mod.gdb.symbol import resolve_addr

        return resolve_addr(address) or None

    @override
    def lookup_symbol(
        self,
        name: str,
        *,
        prefer_static: bool = False,
        type: pwndbg.dbg_mod.SymbolLookupType = pwndbg.dbg_mod.SymbolLookupType.ANY,
        objfile_endswith: str | None = None,
    ) -> pwndbg.dbg_mod.Value | None:
        from pwndbg.dbg_mod.gdb.symbol import Domain
        from pwndbg.dbg_mod.gdb.symbol import lookup_symbol

        domain = {
            pwndbg.dbg_mod.SymbolLookupType.ANY: Domain.ANY,
            pwndbg.dbg_mod.SymbolLookupType.VARIABLE: Domain.VARIABLE,
            pwndbg.dbg_mod.SymbolLookupType.FUNCTION: Domain.FUNCTION,
        }[type]
        try:
            if (
                val := lookup_symbol(
                    name,
                    prefer_static=prefer_static,
                    domain=domain,
                    objfile_endswith=objfile_endswith,
                )
            ) is not None:
                return GDBValue(val)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)
        return None

    @override
    def get_function_boundaries(self, address: int) -> tuple[int, int] | None:
        block = gdb.block_for_pc(address)

        if block is not None:
            # Find the top-level function that this block resides in
            while block.superblock is not None and block.superblock.function is not None:
                block = block.superblock

            return block.start, block.end

        return None

    @override
    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        # In GDB, process-level lookups for types are always global.
        #
        # Additionally, the GDB type lookup function only ever returns the first
        # match, so this will always return a list with one element.
        try:
            return [GDBType(gdb.lookup_type(name))]
        except gdb.error:
            return []

    @override
    def arch(self) -> ArchDefinition:
        import pwndbg.aglib.proc
        import pwndbg.aglib.typeinfo

        ptrsize = pwndbg.aglib.typeinfo.ptrsize
        not_exactly_arch = False

        endian: Literal["little", "big"] = None
        if "little" in gdb.execute("show endian", to_string=True).lower():
            endian = "little"
        else:
            endian = "big"

        if pwndbg.aglib.proc.alive():
            arch = gdb.newest_frame().architecture().name()
        else:
            arch = gdb.execute("show architecture", to_string=True).strip()
            not_exactly_arch = True

        arch = arch.lower()

        arch_attributes = []

        if arch.startswith("mips:"):
            isa = arch[5:]

            if (attribute := gdb_mips_to_arch_attribute_map.get(isa)) is not None:
                arch_attributes.append(attribute)
            else:
                message.warn(
                    f"Warning: unable to detect the corrects MIPS variant from GDB architecture '{arch}'\n"
                    "Instruction disassembly may be inaccurate\n"
                    "Please create a GitHub issue including the output of `pi gdb.newest_frame().architecture().name()`"
                )

        # Below, we fix the fetched architecture
        for match in gdb_architecture_name_fixup_list:
            if match in arch:
                # Distinguish between Cortex-M and other ARM
                # When GDB detects correctly Cortex-M processes, it will label them with `arm*-m`, such as armv7e-m
                # However, GDB will sometimes fail to correctly label Cortex-M binaries properly, and says it's simply 'arm'.
                # Internally, GDB still detects the processes as Cortex-M, as it can access .xpsr, but it doesn't
                # appear to expose this in information through any command/API. Since Cortex-M has the .xpsr flags register
                # instead of .cpsr, we will check if it's present.
                # See: https://github.com/pwndbg/pwndbg/issues/2153
                if match == "arm" and (
                    "-m" in arch or pwndbg.aglib.regs.read_reg("xpsr") is not None
                ):
                    match = "armcm"
                elif match.startswith("riscv:"):
                    match = match[6:]
                elif match == "riscv":
                    # If GDB doesn't detect the width, it will just say `riscv`.
                    match = "rv64"
                elif match in {"iwmmxt", "iwmmxt2", "xscale"}:
                    match = "arm"
                elif match == "rs6000":
                    # The RS/6000 architecture is compatible with the PowerPC common
                    match = "powerpc"
                elif match == "s390:64-bit":
                    match = "s390x"
                return ArchDefinition(
                    name=match,  # type: ignore[arg-type]
                    ptrsize=ptrsize,
                    endian=endian,
                    platform=Platform.LINUX,
                    attributes=arch_attributes,
                )

        if not_exactly_arch:
            raise RuntimeError(f"Could not deduce architecture from: {arch}")

        return ArchDefinition(
            name=arch,  # type: ignore[arg-type]
            ptrsize=ptrsize,
            endian=endian,
            platform=Platform.LINUX,
            attributes=arch_attributes,
        )

    @override
    def break_at(
        self,
        location: pwndbg.dbg_mod.BreakpointLocation | pwndbg.dbg_mod.WatchpointLocation,
        stop_handler: Callable[[pwndbg.dbg_mod.StopPoint], bool] | None = None,
        internal: bool = False,
    ) -> pwndbg.dbg_mod.StopPoint:
        # GDB does not support creating new breakpoints in the middle of a
        # breakpoint stop handler[1]. Catch that case and throw an exception.
        #
        # [1]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Breakpoints-In-Python.html#Breakpoints-In-Python
        if self.in_bpwp_stop_handler:
            raise pwndbg.dbg_mod.Error(
                "Creating new Breakpoints/Watchpoints while in a stop handler is not allowed in GDB"
            )

        if isinstance(location, pwndbg.dbg_mod.BreakpointLocation):
            bp = BreakpointAdapter(
                f"*{location.address:#x}",
                gdb.BP_BREAKPOINT,
                internal=internal,
            )
        elif isinstance(location, pwndbg.dbg_mod.WatchpointLocation):
            if location.watch_read and location.watch_write:
                c = gdb.WP_ACCESS
            elif location.watch_write:
                c = gdb.WP_WRITE
            elif location.watch_read:
                c = gdb.WP_READ

            bp = BreakpointAdapter(
                f"(char[{location.size}])*{location.address}",
                gdb.BP_WATCHPOINT,
                wp_class=c,
                internal=internal,
            )

        if internal:
            bp.silent = True

        sp = GDBStopPoint(bp, self)

        if stop_handler is not None:

            def handler():
                self.in_bpwp_stop_handler = True
                stop = stop_handler(sp)
                self.in_bpwp_stop_handler = False
                return stop
        else:

            def handler():
                return True

        bp.stop_handler = handler

        return sp

    @override
    def trace_ret(self, stop_handler: Callable[[], bool] | None = None, internal: bool = False):
        if stop_handler is None:

            def stop_handler():
                return True

        FinishpointAdapter(stop_handler, internal)

    @override
    def is_linux(self) -> bool:
        # Detect current ABI of client side by 'show osabi'
        #
        # Examples of strings returned by `show osabi`:
        # 'The current OS ABI is "auto" (currently "GNU/Linux").\nThe default OS ABI is "GNU/Linux".\n'
        # 'The current OS ABI is "GNU/Linux".\nThe default OS ABI is "GNU/Linux".\n'
        # 'El actual SO ABI es «auto» (actualmente «GNU/Linux»).\nEl SO ABI predeterminado es «GNU/Linux».\n'
        # 'The current OS ABI is "auto" (currently "none")'
        #
        # As you can see, there might be GDBs with different language versions
        # and so we have to support it there too.
        # Lets assume and hope that `current osabi` is returned in first line in all languages...
        abi = gdb.execute("show osabi", to_string=True).split("\n")[0]

        # Currently we support those osabis:
        # 'GNU/Linux': linux
        # 'none': bare metal

        return "GNU/Linux" in abi

    @override
    def disasm(self, address: int) -> pwndbg.dbg_mod.DisassembledInstruction | None:
        # Currently the type returned by GDB here maps correctly to the type
        # returned by this function, so we don't have to do any extra work.
        #
        # That type is defined in
        # https://sourceware.org/gdb/current/onlinedocs/gdb.html/Architectures-In-Python.html#Architectures-In-Python
        ins: pwndbg.dbg_mod.DisassembledInstruction = (
            gdb.newest_frame().architecture().disassemble(address)[0]
        )
        return ins

    @override
    def module_section_locations(self) -> list[tuple[int, int, str, str]]:
        global pwndbg
        import pwndbg.gdblib.info

        result = []
        for section in pwndbg.gdblib.info.sections():
            result.append(
                (
                    section.start,
                    section.size,
                    section.section,
                    pwndbg.lib.path.clean_path(section.objfile),
                )
            )

        return result

    @override
    def main_module_name(self) -> str | None:
        # Can GDB ever return a different value here from what we'd get with
        # `info files`, give or take a "remote:"?
        if self.alive() and not pwndbg.aglib.qemu.is_qemu_kernel():
            exe = gdb.execute("info proc exe", to_string=True)
            return exe[exe.find("exe = '") + 7 : exe.rfind("'")]
        return gdb.current_progspace().filename

    @override
    def main_module_entry(self) -> int | None:
        import pwndbg.gdblib.info

        for line in pwndbg.gdblib.info.files().splitlines():
            if "Entry point" in line:
                entry_point = int(line.split()[-1], 16)

                # PIE entry points are sometimes reported as an
                # offset from the module base.
                if entry_point < 0x10000:
                    break

                return entry_point

        return None

    @override
    def is_dynamically_linked(self) -> bool:
        out = gdb.execute("info dll", to_string=True)
        return "No shared libraries loaded at this time." not in out

    @override
    def dispatch_execution_controller(
        self, procedure: Callable[[pwndbg.dbg_mod.ExecutionController], Coroutine[Any, Any, None]]
    ):
        # GDB isn't nearly as finnicky as LLDB when it comes to us controlling
        # the execution of the inferior, so we can safely mostly ignore all of
        # the async plumbing and drive the coroutine by just iterating over it.
        #
        # Aditionally, the Debugger-agnostic API allows us enough freedom in how
        # we schedule execution of the controller that running it immediately is
        # perfectly acceptable. So that's what we do.

        coroutine = procedure(EXECUTION_CONTROLLER)
        while True:
            try:
                # We don't need to bother communicating with the coroutine, as
                # it doesn't yield anything we care about.
                coroutine.send(None)
            except (StopIteration, CancelledError):
                # We're done.
                break

    @override
    def add_symbol_file(self, path: str, base: int | None = None) -> None:
        if base is None:
            gdb.execute(f"add-symbol-file {path}", to_string=True)
            return
        gdb.execute(f"add-symbol-file {path} {base}", to_string=True)

    @override
    def remove_symbol_file(self, path: str) -> bool:
        resp: str = gdb.execute(f"remove-symbol-file {path}", to_string=True)
        if "No symbol file found" in resp:
            return False
        return True

    @override
    def runcmd(self, cmd: str) -> str:
        return gdb.execute(cmd, to_string=True)


class GDBExecutionController(pwndbg.dbg_mod.ExecutionController):
    @override
    async def single_step(self):
        # TODO: disable GDB ugly output
        gdb.execute("si")

        # Check if the program stopped because of the step we just took. If it
        # stopped for any other reason, we should propagate a cancellation error
        # to the task and give it a chance to respond.
        if "It stopped after being stepped" not in gdb.execute("info program", to_string=True):
            raise CancelledError()

    @override
    async def cont(self, until: pwndbg.dbg_mod.StopPoint):
        # TODO: disable GDB ugly output
        gdb.execute("continue")

        # Check if the program stopped because of the breakpoint we were given,
        # and, just like for the single step, propagate a cancellation error if
        # it stopped for any other reason.
        assert isinstance(until, GDBStopPoint)
        if f"It stopped at breakpoint {until.inner.number}" not in gdb.execute(
            "info program", to_string=True
        ):
            raise CancelledError()

    @override
    async def cont_selected_thread(self, until: pwndbg.dbg_mod.StopPoint):
        from pwndbg.gdblib.scheduler import lock_scheduler

        with lock_scheduler():
            # TODO: disable GDB ugly output
            gdb.execute("continue")

        # Check if the program stopped because of the breakpoint we were given,
        # and, just like for the single step, propagate a cancellation error if
        # it stopped for any other reason.
        assert isinstance(until, GDBStopPoint)
        if f"It stopped at breakpoint {until.inner.number}" not in gdb.execute(
            "info program", to_string=True
        ):
            raise CancelledError()


# Like in LLDB, we only need a single instance of the execution controller.
EXECUTION_CONTROLLER = GDBExecutionController()


class GDBCommand(gdb.Command):
    def __init__(
        self,
        debugger: GDB,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
        subcommand_names: list[str] | None,
    ):
        # We can't do `list[str] = []` in the signature because python..
        self.debugger = debugger
        self.handler = handler
        self.__doc__ = doc
        if subcommand_names is None:
            super().__init__(name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)
        else:
            self.subcommand_names: list[str] = subcommand_names
            super().__init__(name, gdb.COMMAND_USER)

    def invoke(self, args: str, from_tty: bool) -> None:
        self.handler(self.debugger, args, from_tty)

    def complete(self, text: str, word: str | None):
        # https://sourceware.org/gdb/current/onlinedocs/gdb.html/CLI-Commands-In-Python.html#CLI-Commands-In-Python:~:text=Command%2Ecomplete
        # > `text` holds the complete command line up to the cursor’s location
        # > `word` holds the last word of the command line
        # The description is kind of misleading. If you type `slab li ny<TAB>`
        # you will get text="li ny", word="ny".
        # Actually, the function seems to be called twice for some reason, the first invocation having
        # word=None. Why?
        # Since we only support one level of subcommand completion (i.e. we dont support subsubcommand completion),
        # we don't really care about the text and word distinction.
        # Correction (#3751): We have to handle the `text != word` case to properly autocomplete stuff like
        # `knft list-<tab>` (text="list-", word="").

        if word is None:
            return []
        if text == "":
            # Return all subcommands
            return self.subcommand_names

        # Find all with matching prefix

        # We need to calculate `comp_start` to handle stuff like `knft list-flowtables`
        # and only return the matched word. I.e. `knft list-f<tab>` should return "flowtables"
        # not "list-flowtables".
        comp_start: int = len(text) - len(word)
        return [valid[comp_start:] for valid in self.subcommand_names if valid.startswith(text)]


class GDBCommandHandle(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, command: gdb.Command):
        self.command = command

    def remove(self) -> None:
        # GDB doesn't support command removal.
        pass


class GDBType(pwndbg.dbg_mod.Type):
    CODE_MAPPING = {
        gdb.TYPE_CODE_BOOL: pwndbg.dbg_mod.TypeCode.BOOL,
        gdb.TYPE_CODE_INT: pwndbg.dbg_mod.TypeCode.INT,
        gdb.TYPE_CODE_UNION: pwndbg.dbg_mod.TypeCode.UNION,
        gdb.TYPE_CODE_STRUCT: pwndbg.dbg_mod.TypeCode.STRUCT,
        gdb.TYPE_CODE_ENUM: pwndbg.dbg_mod.TypeCode.ENUM,
        gdb.TYPE_CODE_TYPEDEF: pwndbg.dbg_mod.TypeCode.TYPEDEF,
        gdb.TYPE_CODE_PTR: pwndbg.dbg_mod.TypeCode.POINTER,
        gdb.TYPE_CODE_ARRAY: pwndbg.dbg_mod.TypeCode.ARRAY,
        gdb.TYPE_CODE_FUNC: pwndbg.dbg_mod.TypeCode.FUNC,
        # TODO: support `TYPE_CODE_METHOD` differently later?
        gdb.TYPE_CODE_METHOD: pwndbg.dbg_mod.TypeCode.FUNC,
    }

    def __init__(self, inner: gdb.Type):
        self.inner = inner

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, GDBType), "tried to compare GDBType to other type"
        other: GDBType = rhs

        return self.inner == other.inner

    @property
    @override
    def name_identifier(self) -> str | None:
        if not self.inner.name:
            return None
        return self.inner.name

    @property
    @override
    def name_to_human_readable(self) -> str:
        if self.inner.name:
            # If named struct/enum/typedef/etc
            return self.inner.name
        return str(self.inner)

    @property
    @override
    def sizeof(self) -> int:
        return self.inner.sizeof

    @property
    @override
    def alignof(self) -> int:
        return self.inner.alignof

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        try:
            assert self.inner.code in GDBType.CODE_MAPPING, "missing mapping for type code"
            return GDBType.CODE_MAPPING[self.inner.code]
        except Exception:
            # TODO: log invalid types
            return pwndbg.dbg_mod.TypeCode.INVALID

    @override
    def func_arguments(self) -> list[pwndbg.dbg_mod.Type] | None:
        if self.code != pwndbg.dbg_mod.TypeCode.FUNC:
            raise TypeError("only available for function type")

        # Type without debug info
        # https://github.com/bminor/binutils-gdb/blob/c2dbc2929e87557f8bc030f6f010d67b19f99f12/gdb/gdbtypes.c#L6052-L6072
        is_missing_debug_info = self.inner.name and self.inner.name.endswith(", no debug info>")
        if is_missing_debug_info:
            return None

        args: list[gdb.Field] = self.inner.fields()
        if not args:
            return []
        return [GDBType(arg.type) for arg in args]

    @override
    def fields(self) -> list[pwndbg.dbg_mod.TypeField]:
        return [
            pwndbg.dbg_mod.TypeField(
                field.bitpos if hasattr(field, "bitpos") else 0,
                field.name,
                GDBType(field.type),
                field.parent_type,
                field.enumval if hasattr(field, "enumval") else 0,
                field.artificial,
                field.is_base_class,
                field.bitsize,
            )
            for field in self.inner.fields()
        ]

    @override
    def has_field(self, name: str) -> bool:
        # For GDB, we can do a little better than the default implementation, as
        # it has a specific convenience function that checks for this condition
        # exactly.
        try:
            return gdb.types.has_field(self.inner, name)
        except TypeError:
            # GDB throws an exception for stuff that does not resolve to a struct or union
            # after typedefs have been stripped.
            # https://git.sr.ht/~sourceware/binutils-gdb/tree/05c660d1d7ca754a9607084e606c263b1fd74a94/item/gdb/python/lib/gdb/types.py#L61
            return False

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        # GDB's .array function expects the inclusive upper bound of the array,
        # not the number of elements.
        return GDBType(self.inner.array(count - 1))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.pointer())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.strip_typedefs())

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.target())

    @override
    def keys(self) -> list[str]:
        return list(self.inner.keys())

    @override
    def offsetof(self, field_name: str) -> int | None:
        # In LLDB this code don't work
        value = pwndbg.dbg.selected_inferior().create_value(0, self.pointer())
        try:
            addr = value[field_name].address
        except pwndbg.dbg_mod.Error:
            # error: `There is no member named field_name`
            return None

        if addr is None:
            raise pwndbg.dbg_mod.Error("bug, this should no happen")

        return int(addr)


class GDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: gdb.Value):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        val = self.inner.address
        if val is None:
            return None
        return GDBValue(val)

    @property
    @override
    def is_optimized_out(self) -> bool:
        return self.inner.is_optimized_out

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        if (
            self.type.code == pwndbg.dbg_mod.TypeCode.POINTER
            and self.type.target().code == pwndbg.dbg_mod.TypeCode.FUNC
        ):
            raise pwndbg.dbg_mod.Error("Dereference to function type is not allowed")

        return GDBValue(self.inner.dereference())

    @override
    def string(self) -> str:
        try:
            return self.inner.string()
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def value_to_human_readable(self) -> str:
        try:
            return str(self.inner)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def fetch_lazy(self) -> None:
        self.inner.fetch_lazy()

    @override
    def __int__(self) -> int:
        try:
            return int(self.inner)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        assert isinstance(type, GDBType)
        type: GDBType = type

        if type.code == pwndbg.dbg_mod.TypeCode.FUNC:
            raise pwndbg.dbg_mod.Error("Cast to function type is not allowed, use pointer")

        try:
            return GDBValue(self.inner.cast(type.inner))
        except gdb.error as e:
            # GDB casts can fail.
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __add__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(self.inner + rhs)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __sub__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(self.inner - rhs)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def __getitem__(self, key: str | int) -> pwndbg.dbg_mod.Value:
        if isinstance(key, int) and self.inner.type.strip_typedefs().code == gdb.TYPE_CODE_STRUCT:
            # GDB doesn't normally support indexing fields in a struct by int,
            # so we nudge it a little.
            key = self.inner.type.fields()[key]

        try:
            return GDBValue(self.inner[key])
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)


def _gdb_event_registry_from_event_type(ty: EventType) -> gdb.EventRegistry[Any]:
    """
    Returns the GDB event registry that corresponds to the given event type.
    """
    match ty:
        case EventType.EXIT:
            return gdb.events.exited
        case EventType.CONTINUE:
            return gdb.events.cont
        case EventType.START:
            # Pwndbg installs this one when it loads the GDB event support module.
            #
            # We should never run this function before it gets loaded, but, if this
            # ever changes by mistake, we want the mistake to be caught early, with
            # a clear error.
            assert hasattr(gdb.events, "start"), (
                "gdb.events.start is missing. Did the Pwndbg GDB event code not get loaded?"
            )
            return gdb.events.start
        case EventType.STOP:
            return gdb.events.stop
        case EventType.NEW_MODULE:
            return gdb.events.new_objfile
        case EventType.MEMORY_CHANGED:
            return gdb.events.memory_changed
        case EventType.REGISTER_CHANGED:
            return gdb.events.register_changed
        case EventType.SUSPEND_ALL:
            assert hasattr(gdb.events, "suspend_all"), (
                "gdb.events.suspend_all is missing. Did the Pwndbg GDB event code not get loaded?"
            )
            return gdb.events.suspend_all
        case _:
            raise NotImplementedError(f"unknown event type {ty}")


class GDB(pwndbg.dbg_mod.Debugger):
    def _disable_gdbinit_loading(self) -> tuple[bool, bool]:
        import os

        import psutil

        disable_home_gdbinit = 0
        disable_any_gdbinit = 0
        proc = psutil.Process(os.getpid())
        for arg in proc.cmdline():
            if arg in ("-args", "--args"):
                break
            if arg in ("-nh", "--nh"):
                disable_home_gdbinit += 1
            elif arg in ("-nx", "--nx", "-n", "--n"):
                disable_any_gdbinit += 1

        if disable_any_gdbinit == 0:
            # The `--nx` option is added only in pwndbg-portable mode.
            # This check allows using OLD syntax, eg: `source /path/to/pwndbg/gdbinit.py`, from ~/.gdbinit
            return True, True

        return disable_any_gdbinit >= 2, disable_home_gdbinit >= 1

    def _load_gdbinit(self):
        # Emulate how `gdb` loads `.gdbinit` files (home and local)
        disable_any, disable_home = self._disable_gdbinit_loading()
        if disable_any:
            return

        config_home = environ.get("XDG_CONFIG_HOME", Path("~/.config").expanduser().resolve())
        home_file = (Path(config_home) / "gdb" / "gdbinit").resolve()
        if not home_file.exists():
            home_file = Path("~/.gdbinit").expanduser().resolve()
        local_file = Path("./.gdbinit").resolve()

        def load_source(file_path: str):
            try:
                gdb.execute(f"source {file_path}")
            except gdb.error as e:
                print(e)

        is_home_loaded = False
        if not disable_home and home_file.exists():
            load_source(str(home_file))
            is_home_loaded = True

        disable_local = not gdb.parameter("auto-load local-gdbinit")
        try:
            should_load_local = (
                not disable_local
                and local_file.exists()
                and not (is_home_loaded and home_file.samefile(local_file))
            )
        except PermissionError:
            print(
                message.warn(
                    f"WARNING: Skipped loading {local_file} because you don't have the correct permissions."
                )
            )
            should_load_local = False

        if should_load_local:
            load_source("./.gdbinit")

    @override
    def setup(self):
        import pwnlib.update

        pwnlib.update.disabled = True

        from pwndbg.aglib import load_aglib
        from pwndbg.commands import load_commands

        load_gdblib()
        load_aglib()
        load_commands()

        # Register event hooks.
        # (We can't do them in this file because pwndbg.dbg isn't initialized yet.)
        from pwndbg.dbg_mod.gdb import hooks as hooks

        # Importing `pwndbg.gdblib.prompt` ends up importing code that has the
        # side effect of setting a command up. Because command setup requires
        # `pwndbg.dbg` to already be set, and this module is used as part of the
        # process of setting it, we have to wait, and do the import as part of
        # this method.
        from pwndbg.gdblib import prompt

        prompt.set_prompt()

        pre_commands = """
        set auto-load safe-path /
        set confirm off
        set verbose off
        set pagination off
        set history save on
        set follow-fork-mode child
        set backtrace past-main on
        set step-mode on
        set print pretty on
        set output-radix 16
        handle SIGALRM nostop print nopass
        handle SIGBUS  stop   print nopass
        handle SIGPIPE nostop print nopass
        handle SIGSEGV stop   print nopass
        """

        for line in pre_commands.strip().splitlines():
            gdb.execute(line)

        # debuginfod may not be compiled in (e.g. bare-metal cross GDB)
        with suppress(gdb.error):
            gdb.execute("set debuginfod enabled on")

        # This may throw an exception, see pwndbg/pwndbg#27
        with suppress(gdb.error):
            gdb.execute("set disassembly-flavor intel")

        from pwndbg.gdblib.tui import setup as tui_setup

        tui_setup()

        # Reading Comment file
        from pwndbg.commands import comments

        comments.init()

        from pwndbg.gdblib import config_mod

        config_mod.init_params()

        from pwndbg.dbg_mod.gdb import debug_sym as debug_sym

        self._load_gdbinit()

        # show_hint must be called after loading ~/.gdbinit, this order allow disabling show_hint
        prompt.show_hint()

    @override
    def add_command(
        self,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
        subcommand_names: list[str] | None = None,
    ) -> pwndbg.dbg_mod.CommandHandle:
        command = GDBCommand(self, name, handler, doc, subcommand_names)
        return GDBCommandHandle(command)

    @override
    def history(self, last: int = 10) -> list[tuple[int, str]]:
        # GDB displays commands in groups of 10. We might want more than that,
        # so we fetch multiple blocks of 10 and assemble them into the final
        # history in a second step.
        parsed_blocks = []
        parsed_lines_count = 0
        parsed_lines_min = None
        parsed_lines_max = None
        parsed_lines_base = None

        while parsed_lines_count < last:
            # Fetch and parse the block we're currently interested in.
            base = f" {parsed_lines_base}" if parsed_lines_base else ""

            lines = gdb.execute(f"show commands{base}", from_tty=False, to_string=True)
            lines = lines.splitlines()

            parsed_lines = []
            for line in lines:
                num_cmd = line.split(maxsplit=1)

                try:
                    number = int(num_cmd[0])
                except ValueError:
                    # In rare cases GDB will output a warning after executing `show commands`
                    # (i.e. "warning: (Internal error: pc 0x0 in read in CU, but not in
                    # symtab.)").
                    return []
                # In rare cases GDB stores a number with no command, and the split()
                # then only returns one element. We can safely ignore these.
                command = num_cmd[1] if len(num_cmd) > 1 else ""

                parsed_lines.append((number, command))

            # We have nothing more to parse if GDB gives us nothing here.
            if len(parsed_lines) == 0:
                break

            # Set the maximum command index we know about. This is simply the
            # last element of the first block.
            if not parsed_lines_max:
                parsed_lines_max = parsed_lines[-1][0]

            # Keep track of the minimum command index we've seen.
            #
            # This is usually the first element in the most recent block, but
            # GDB isn't very clear about whether running commands with
            # `gdb.execute` affects the command history, and what the exact size
            # of the command history is. This means that, at the very end, the
            # first index in the last block might be one greater than the last
            # index in the second-to-last block.
            #
            # Additionally, the value of the first element being greater than
            # the minimum also means that we reached the end of the command
            # history on the last block, can break out of the loop early, and
            # don't even need to bother with this block.
            if parsed_lines_min:
                if parsed_lines[0][0] < parsed_lines_min:
                    parsed_lines_min = parsed_lines[0][0]
                else:
                    break
            else:
                parsed_lines_min = parsed_lines[0][0]

            parsed_blocks.append(parsed_lines)
            parsed_lines_count += len(parsed_lines)

            # If we've just pulled the block with command index 0, we know we
            # can't possibly go back any farther.
            if parsed_lines_base == 0:
                break

            # The way GDB displays the command history is _weird_. The argument
            # we pass to `show commands <arg>` is the index of the 6th element
            # in the block, meaning we'll get a block whose values range from
            # at most <arg> - 5 to at most <arg> + 4, inclusive.
            #
            # Given that we want the first element in this block to the just one
            # past the maximum range of the block returned by the next arguemnt,
            # and that we know the last element in a block is at most <arg> + 4,
            # we can subtract five from its index to land in the right spot.
            parsed_lines_base = max(0, parsed_lines[0][0] - 5)

        # We've got nothing.
        if len(parsed_blocks) == 0:
            return []

        # Sort the elements in the block into the final history array.
        remaining = parsed_lines_max - parsed_lines_min + 1
        plines: list[tuple[int, str]] = [None] * remaining
        while remaining > 0 and len(parsed_blocks) > 0:
            block = parsed_blocks.pop()
            for pline in block:
                index = pline[0] - parsed_lines_min
                if not plines[index]:
                    plines[pline[0] - parsed_lines_min] = pline
                    remaining -= 1

        # If this fails, either some of our assumptions were wrong, or GDB is
        # doing something funky with the output, either way, not good.
        assert remaining == 0, "There are gaps in the command history"

        return plines[-last:]

    @override
    def lex_args(self, command_line: str) -> list[str]:
        return gdb.string_to_argv(command_line)

    @override
    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        thread = gdb.selected_thread()
        if thread:
            return GDBThread(thread)
        return None

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            frame = gdb.selected_frame()
            if frame:
                return GDBFrame(frame)
        except gdb.error:
            pass
        return None

    def commands(self):
        current_pagination = gdb.execute("show pagination", to_string=True)
        current_pagination = current_pagination.split()[-1].rstrip(
            "."
        )  # Take last word and skip period

        gdb.execute("set pagination off")
        command_list = gdb.execute("help all", to_string=True).strip().split("\n")
        existing_commands: set[str] = set()
        for line in command_list:
            line = line.strip()
            # Skip non-command entries
            if not line or line.startswith(("Command class:", "Unclassified commands")):
                continue
            command = line.split()[0]
            existing_commands.add(command)
        gdb.execute(f"set pagination {current_pagination}")  # Restore original setting
        return existing_commands

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process:
        return GDBProcess(gdb.selected_inferior())

    @override
    def is_gdblib_available(self):
        return True

    @override
    def has_event_type(self, ty: EventType) -> bool:
        # Currently GDB supports all event types.
        return True

    @override
    def event_handler(
        self,
        event_type: EventType,
        priority: EventHandlerPriority = EventHandlerPriority.STANDARD,
    ) -> Callable[[Callable[..., None]], Callable[..., None]]:
        import pwndbg.gdblib.events

        event_registry: gdb.EventRegistry[Any] = _gdb_event_registry_from_event_type(event_type)
        return pwndbg.gdblib.events.event_handler_factory(event_registry, event_type.name, priority)

    @override
    @contextmanager
    def ctx_suspend_once(self):
        pwndbg.gdblib.prompt.context_shown = True

    @override
    def suspend_events(self, ty: EventType) -> None:
        pwndbg.gdblib.events.pause(_gdb_event_registry_from_event_type(ty))

    @override
    def resume_events(self, ty: EventType) -> None:
        pwndbg.gdblib.events.unpause(_gdb_event_registry_from_event_type(ty))

    @override
    def set_sysroot(self, sysroot: str) -> bool:
        try:
            gdb.execute(f"set sysroot {sysroot}", from_tty=False)
            # Assume it worked..
            return True
        except gdb.error:
            return False

    @override
    def supports_breakpoint_creation_during_stop_handler(self) -> bool:
        return False

    @override
    def breakpoint_locations(self) -> list[pwndbg.dbg_mod.BreakpointLocation]:
        bps = gdb.breakpoints()
        locations: list[pwndbg.dbg_mod.BreakpointLocation] = []
        for bp in bps:
            if (
                bp.is_valid()
                and bp.enabled
                and bp.type in (gdb.BP_BREAKPOINT, gdb.BP_HARDWARE_BREAKPOINT)
                and bp.visible
            ):
                # GDB 13.1+
                if hasattr(bp, "locations"):
                    for location in bp.locations:
                        locations.append(pwndbg.dbg_mod.BreakpointLocation(location.address))
                else:
                    # Num     Type           Disp Enb Address            What
                    # 1       breakpoint     keep y   0x00007ffff7e90840 in __GI___libc_read at ../sysdeps/unix/sysv/linux/read.c:26
                    bp_locations = gdb.execute(
                        f"info breakpoint {bp.number}", to_string=True
                    ).split("\n")
                    for line in bp_locations:
                        try:
                            address = int(line.split()[4], 16)
                            locations.append(pwndbg.dbg_mod.BreakpointLocation(address))
                        except (IndexError, ValueError):
                            # Ignore lines that don't have an address.
                            pass
        return locations

    @override
    def name(self) -> pwndbg.dbg_mod.DebuggerType:
        return pwndbg.dbg_mod.DebuggerType.GDB

    @override
    def x86_disassembly_flavor(self) -> Literal["att", "intel"]:
        try:
            flavor = gdb.execute("show disassembly-flavor", to_string=True).lower().split('"')[1]
        except gdb.error as e:
            if str(e).find("disassembly-flavor") > -1:
                flavor = "intel"
            else:
                raise pwndbg.dbg_mod.Error(e)

        if flavor not in {"att", "intel"}:
            raise pwndbg.dbg_mod.Error(f"unrecognized disassembly flavor '{flavor}'")

        literal: Literal["att", "intel"] = flavor
        return literal

    @override
    def string_limit(self) -> int:
        message = gdb.execute("show print elements", from_tty=False, to_string=True)
        message = message.split("\n")[0].split()[-1]
        message = message.strip(".")
        if message == "unlimited":
            return 0
        return int(message)

    @override
    def addrsz(self, address: Any) -> str:
        address = int(address) & pwndbg.aglib.arch.ptrmask
        return f"%#{2 * pwndbg.aglib.arch.ptrsize}x" % address

    @override
    def get_cmd_window_size(self) -> tuple[int | None, int | None]:
        """Get the size of the command window.

        GDB keeps these parameters up to date with the actual window size
        of the command output. This is the full terminal size in CLI mode
        or the size of the cmd window in TUI mode.

        When the window size is set to be unlimited (0), the parameter
        is None.
        """
        width = gdb.parameter("width")
        height = gdb.parameter("height")
        return (
            height if height is None else int(height),
            width if width is None else int(width),
        )

    @override
    @property
    def pre_ctx_lines(self) -> int:
        # GDB most often prints one line
        # as a "0x000055555556fa8f in main ()"-type message
        return 1

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        if enabled:
            command = "set python print-stack full"
        else:
            command = "set python print-stack message"

        gdb.execute(command, from_tty=True, to_string=True)

    @override
    def set_convenience_var(self, name: str, value: str, type: str | None) -> None:
        """
        Set a convenience variable which will be accessible with $name in the
        debugger.

        Read the docstring in pwndbg.dbg.set_convenience_var()!!

        Surround this function with try/except.
        """
        if type is not None:
            gdb.execute(f"set ${name} = (({type})({value}))")
        else:
            gdb.execute(f"set ${name} = ({value})")
