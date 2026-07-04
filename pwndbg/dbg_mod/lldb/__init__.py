from __future__ import annotations

import bisect
import collections
import enum
import functools
import os
import random
import re
import shlex
import sys
from asyncio import CancelledError
from collections.abc import Awaitable
from collections.abc import Callable
from collections.abc import Coroutine
from collections.abc import Generator
from collections.abc import Iterator
from collections.abc import Sequence
from contextlib import contextmanager
from contextlib import suppress
from pathlib import Path
from typing import Any
from typing import Literal
from typing import TypeVar
from typing import cast

import lldb
from typing_extensions import override

import pwndbg
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.lib.path
from pwndbg.color import message
from pwndbg.dbg_mod import EventHandlerPriority
from pwndbg.dbg_mod import selection
from pwndbg.lib import TypeNotFoundError
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform
from pwndbg.lib.regs import reg_sets
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


# We keep track of the LLDB version for some things we have to gate off behind
# newer versions.
LLDB_VERSION: tuple[int, int] = None


def rename_register(name: str, proc: LLDBProcess) -> str:
    """
    Some register names differ between Pwndbg/GDB and LLDB. This function takes
    in a register name in the Pwndbg/GDB convention and returns the equivalent
    LLDB name for the register.
    """

    if name == "eflags" and proc.arch().name == "x86-64":
        return "rflags"

    # Nothing to change.
    return name


class LLDBRegisters(pwndbg.dbg_mod.Registers):
    groups: lldb.SBValueList
    proc: LLDBProcess

    def __init__(self, groups: lldb.SBValueList, proc: LLDBProcess):
        self.groups = groups
        self.proc = proc

    @override
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        name = rename_register(name, self.proc)

        for i in range(self.groups.GetSize()):
            group = self.groups.GetValueAtIndex(i)
            member = group.GetChildMemberWithName(name)
            if member is not None and member.IsValid():
                return LLDBValue(member, self.proc)

        return None


def _get_frame_stack_variables(frame: lldb.SBFrame) -> tuple[tuple[int, int, str], ...]:
    try:
        # GetVariables(arguments, locals, statics, in_scope_only)
        variables = frame.GetVariables(True, True, False, True)

        result = []
        for i in range(variables.GetSize()):
            var = variables.GetValueAtIndex(i)
            if not var.IsValid():
                continue

            addr = var.GetLoadAddress()
            if addr == lldb.LLDB_INVALID_ADDRESS:
                continue

            size = var.GetType().GetByteSize()
            result.append((int(addr), int(addr) + size, var.GetName()))

        return tuple(result)
    except Exception:
        return ()


class LLDBFrame(pwndbg.dbg_mod.Frame):
    inner: lldb.SBFrame
    proc: LLDBProcess

    def __init__(self, inner: lldb.SBFrame, proc: LLDBProcess):
        assert inner.IsValid()
        self.inner = inner
        self.proc = proc

    @override
    def lookup_symbol(
        self,
        name: str,
        *,
        type: pwndbg.dbg_mod.SymbolLookupType = pwndbg.dbg_mod.SymbolLookupType.ANY,
    ) -> pwndbg.dbg_mod.Value | None:
        # `symbol_name_at_address` encodes offsets as part of the name, handle
        # that here.
        offset = 0
        try:
            idx = name.rindex("+")
            offset = int(name[idx:], 10)
            name = name[:idx]
        except ValueError:
            pass

        value = None
        with suppress(pwndbg.dbg_mod.Error):
            if re.match(r"^[a-zA-Z0-9_.:@*/$]+$", name):
                value = self.evaluate_expression(f"&{name}")

        if value is None:
            # Fallback because `evaluate_expression` may fail to resolve symbols for TLS variables.
            # This issue occurs on certain architectures (e.g., it works fine on x86_64 but fails on aarch64).
            value = self.proc.lookup_symbol(name, type=type)

        if value is not None:
            value += offset

        return value

    @override
    def evaluate_expression(
        self, expression: str, lock_scheduler: bool = False
    ) -> pwndbg.dbg_mod.Value:
        value = self.inner.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value, self.proc)

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return LLDBRegisters(self.inner.GetRegisters(), self.proc)

    @override
    def reg_write(self, name: str, val: int) -> bool:
        if val < 0:
            raise RuntimeError("Tried to write a register with a negative value")

        if name not in pwndbg.aglib.regs:
            return False

        current_reg_set = reg_sets[pwndbg.aglib.arch.name]

        full_reg_name = name
        if reg_info := current_reg_set.full_register_lookup.get(name):
            full_reg_name = reg_info.name

        # Writing to the PC (or any subregister of the PC) using the normal register write flow causes the
        # inner object to be automatically invalidated by LLDB, so we have to
        # handle jumps manually using SBFrame::SetPC.
        if name == "pc" or full_reg_name == current_reg_set.pc:
            ret = self.inner.SetPC(val)
            self.proc.dbg._trigger_event(pwndbg.dbg_mod.EventType.REGISTER_CHANGED)
            return ret

        name = rename_register(name, self.proc)

        # This one is quite bad. LLDB register writes happen through the private
        # API[1]. This means we have to do our register writes using commands,
        # GDB style, and, because the command that writes registers uses the
        # currently selected frame in order to determine the context in which it
        # is going to change values is, we have to some global state frame
        # selection.
        #
        # [1]: https://github.com/llvm/llvm-project/blob/3af26be42e39405d9b3e1023853218dea20b5d1f/lldb/source/Commands/CommandObjectRegister.cpp#L336

        frame = self.inner
        thread = frame.thread
        process = thread.process
        debugger = process.target.debugger

        # First, we select the right target in the debugger.
        with selection(
            process.target,
            lambda: debugger.GetSelectedTarget(),
            lambda t: debugger.SetSelectedTarget(t),
        ):
            # Then, we select the right thread in the process.
            with selection(
                thread,
                lambda: process.GetSelectedThread(),
                lambda t: process.SetSelectedThread(t),
            ):
                # Then, we select the right frame in the thread.
                with selection(
                    frame,
                    lambda: thread.GetSelectedFrame(),
                    lambda f: thread.SetSelectedFrame(f.idx),
                ):
                    # Run the command that sets the value of the register.
                    try:
                        self.proc.dbg._execute_lldb_command(f"register write {name} {val}")
                    except pwndbg.dbg_mod.Error as e:
                        error = str(e)
                        if f"'{name}'" in error and "not found" in error:
                            # Likely "error: Register not found for '{name}'"
                            return False
                        raise pwndbg.dbg_mod.Error(
                            f"could not set value of register '{name}' to '{val}': {error}"
                        )

                    # We know this register got written to, we can trigger this
                    # event.
                    self.proc.dbg._trigger_event(pwndbg.dbg_mod.EventType.REGISTER_CHANGED)

                    # If we set the stack pointer (or a subregister of the stack pointer), the inner object might have been invalidated, try
                    # to restore it, as it should still be the selected frame.
                    if (
                        name == "sp" or full_reg_name == current_reg_set.stack
                    ) and not self.inner.IsValid():
                        self.inner = thread.GetSelectedFrame()
                        assert self.inner.GetSP() == val

                    # Make sure we've caught and handled the special cases in which the inner object
                    # might be invalidated by the command.
                    assert self.inner.IsValid()

                    # This might slow things down, but I'm not entirely sure selecting
                    # the thread in the way we do is enough to make LLDB write to the
                    # right register in all cases, so we check the value of the register
                    # against what we wrote, to be extra safe.
                    assert int(self.regs().by_name(name)) == val, (
                        "wrote to a register, but read back different value. this is a bug"
                    )

                    return True

    @override
    def pc(self) -> int:
        return self.inner.GetPC()

    @override
    def sp(self) -> int:
        return self.inner.GetSP()

    @override
    def start(self) -> int | None:
        import pwndbg.aglib

        # https://lldb.llvm.org/python_api/lldb.SBFrame.html#lldb.SBFrame.GetCFA
        # FIXME: Sometimes returns the middle of the stack frame??
        # https://github.com/pwndbg/pwndbg/issues/3634
        val = self.inner.GetCFA()
        if val == lldb.LLDB_INVALID_ADDRESS:
            return None
        # For some reason returns +8 on top of retaddr, just like GDB.
        # I guess the DWARF just looks like that?
        return val - pwndbg.aglib.arch.ptrsize

    @override
    def parent(self) -> pwndbg.dbg_mod.Frame | None:
        parent = self.inner.get_parent_frame()
        if parent.IsValid():
            return LLDBFrame(self.inner.get_parent_frame(), self.proc)
        return None

    @override
    def child(self) -> pwndbg.dbg_mod.Frame | None:
        index = self.inner.idx - 1
        if index >= 0:
            frame = self.inner.thread.frame[index]
            if frame.IsValid():
                return LLDBFrame(frame, self.proc)

        return None

    @override
    def sal(self) -> tuple[str, int] | None:
        line_entry = self.inner.GetLineEntry()
        if line_entry.IsValid():
            return line_entry.file.fullpath, line_entry.line

        return None

    @override
    @pwndbg.lib.cache.cache_until("forever")
    def stack_variables(self) -> tuple[tuple[int, int, str], ...]:
        return _get_frame_stack_variables(self.inner)

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, LLDBFrame), "tried to compare LLDBFrame to other type"
        other: LLDBFrame = rhs

        return self.inner == other.inner

    @override
    def idx(self) -> int:
        # https://lldb.llvm.org/python_api/lldb.SBFrame.html#lldb.SBFrame.idx
        return self.inner.idx

    @override
    def __hash__(self) -> int:
        # There is a GetFrameID API [1], but it isn't really documented
        # and looking at its implementation [2] does not fill me with confidence.
        # Looking at the SBFrame equality check [3], it uses StackFrame.GetStackID()
        # [4] which updates and returns StackFrame.m_id the comparison of which is
        # implemented here [5]. But I don't see how it guarantees that two frames at
        # the same stack and pc but at different times will be different. Maybe it
        # just doesn't?
        # In any case the StackID class doesn't expose an integer, so we are rolling
        # our own thing.
        # [1] https://lldb.llvm.org/python_api/lldb.SBFrame.html#lldb.SBFrame.GetFrameID
        # [2] https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/lldb/source/API/SBFrame.cpp#L255
        # [3] https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/lldb/source/API/SBFrame.cpp#L585
        # [4] https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/lldb/source/Target/StackFrame.cpp#L154
        # [5] https://github.com/llvm/llvm-project/blob/1deee91bf52ca15e47b59a2929e5e5a323f4864c/lldb/source/Target/StackID.cpp#L53
        # I think a (number of stops, thread index, frame index) tuple uniquely identifies a stack frame.
        # There probably won't be >= 65,536 stack frames in a thread stack, or
        # >= 65,536 threads in a process.
        # The `pwndbg.dbg_mod.number_of_stops_since_birth` part might not be necessary, because
        # if you are comparing frames from different stops that means your code is buggy; but it
        # lets me sleep at night better.
        return (
            self.idx()
            + (self.inner.thread.idx << 16)
            + (pwndbg.dbg_mod.number_of_stops_since_birth << 32)
        )


class LLDBThread(pwndbg.dbg_mod.Thread):
    inner: lldb.SBThread
    proc: LLDBProcess

    def __init__(self, inner: lldb.SBThread, proc: LLDBProcess):
        self.inner = inner
        self.proc = proc

    @override
    @contextmanager
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        if self.inner.GetNumFrames() <= 0:
            raise pwndbg.dbg_mod.Error("no frames")

        yield LLDBFrame(self.inner.GetFrameAtIndex(0), self.proc)

    @override
    def ptid(self) -> int | None:
        return self.inner.id

    @override
    def index(self) -> int:
        return self.inner.idx

    @override
    def siginfo(self) -> SigInfo | None:
        lldb_siginfo = self.inner.GetSiginfo()

        if lldb_siginfo.error.Fail():
            # It can happen that LLDB fails to retrieve the signal information
            # e.g. on QEMU kernel debugging:
            # lldb_siginfo.error.GetCString() == "qXfer:siginfo:read not supported"
            # Also reproducable on MacOS on normal binaries.
            return None

        int_cast: Callable[[str], int] = lambda x: int(x, 16) if x.startswith("0x") else int(x)

        si_signo = int_cast(lldb_siginfo.GetChildMemberWithName("si_signo").value)
        si_errno = int_cast(lldb_siginfo.GetChildMemberWithName("si_errno").value)
        si_code = int_cast(lldb_siginfo.GetChildMemberWithName("si_code").value)

        sifields = lldb_siginfo.GetChildMemberWithName("_sifields")

        kill_field = sifields.GetChildMemberWithName("_kill")
        kill = SigInfoKill(
            si_pid=int_cast(kill_field.GetChildMemberWithName("si_pid").value),
            si_uid=int_cast(kill_field.GetChildMemberWithName("si_uid").value),
        )

        timer_field = sifields.GetChildMemberWithName("_timer")
        timer_sigval = timer_field.GetChildMemberWithName("si_sigval")
        timer = SigInfoTimer(
            si_tid=int_cast(timer_field.GetChildMemberWithName("si_tid").value),
            si_overrun=int_cast(timer_field.GetChildMemberWithName("si_overrun").value),
            si_sigval=SigInfoSigVal(
                sival_int=int_cast(timer_sigval.GetChildMemberWithName("sival_int").value),
                sival_ptr=int_cast(timer_sigval.GetChildMemberWithName("sival_ptr").value),
            ),
        )

        rt_field = sifields.GetChildMemberWithName("_rt")
        rt_sigval = rt_field.GetChildMemberWithName("si_sigval")
        rt = SigInfoRt(
            si_pid=int_cast(rt_field.GetChildMemberWithName("si_pid").value),
            si_uid=int_cast(rt_field.GetChildMemberWithName("si_uid").value),
            si_sigval=SigInfoSigVal(
                sival_int=int_cast(rt_sigval.GetChildMemberWithName("sival_int").value),
                sival_ptr=int_cast(rt_sigval.GetChildMemberWithName("sival_ptr").value),
            ),
        )

        sigchld_field = sifields.GetChildMemberWithName("_sigchld")
        sigchld = SigInfoSigChld(
            si_pid=int_cast(sigchld_field.GetChildMemberWithName("si_pid").value),
            si_uid=int_cast(sigchld_field.GetChildMemberWithName("si_uid").value),
            si_status=int_cast(sigchld_field.GetChildMemberWithName("si_status").value),
            si_utime=int_cast(sigchld_field.GetChildMemberWithName("si_utime").value),
            si_stime=int_cast(sigchld_field.GetChildMemberWithName("si_stime").value),
        )

        sigfault_field = sifields.GetChildMemberWithName("_sigfault")
        sigfault = SigInfoSigFault(
            si_addr=int_cast(sigfault_field.GetChildMemberWithName("si_addr").value)
        )

        sigpoll_field = sifields.GetChildMemberWithName("_sigpoll")
        sigpoll = SigInfoSigPoll(
            si_band=int_cast(sigpoll_field.GetChildMemberWithName("si_band").value),
            si_fd=int_cast(sigpoll_field.GetChildMemberWithName("si_fd").value),
        )

        sigsys_field = sifields.GetChildMemberWithName("_sigsys")
        sigsys = SigInfoSigSys(
            call_addr=int_cast(sigsys_field.GetChildMemberWithName("_call_addr").value),
            syscall=int_cast(sigsys_field.GetChildMemberWithName("_syscall").value),
            arch=int_cast(sigsys_field.GetChildMemberWithName("_arch").value),
        )

        siginfo = SigInfo(
            si_signo=si_signo,
            si_errno=si_errno,
            si_code=si_code,
            kill=kill,
            timer=timer,
            rt=rt,
            sigchld=sigchld,
            sigfault=sigfault,
            sigpoll=sigpoll,
            sigsys=sigsys,
        )

        return siginfo


def map_type_code(type: lldb.SBType) -> pwndbg.dbg_mod.TypeCode:
    """
    Determines the type code of a given LLDB SBType.
    """
    c = type.GetTypeClass()

    assert c != lldb.eTypeClassInvalid, "passed eTypeClassInvalid to map_type_code"

    if c == lldb.eTypeClassUnion:
        return pwndbg.dbg_mod.TypeCode.UNION
    if c == lldb.eTypeClassStruct:
        return pwndbg.dbg_mod.TypeCode.STRUCT
    if c == lldb.eTypeClassTypedef:
        return pwndbg.dbg_mod.TypeCode.TYPEDEF
    if c == lldb.eTypeClassPointer:
        return pwndbg.dbg_mod.TypeCode.POINTER
    if c == lldb.eTypeClassArray:
        return pwndbg.dbg_mod.TypeCode.ARRAY
    if c == lldb.eTypeClassEnumeration:
        return pwndbg.dbg_mod.TypeCode.ENUM
    if c == lldb.eTypeClassFunction:
        return pwndbg.dbg_mod.TypeCode.FUNC

    basic_type = type.GetCanonicalType().GetBasicType()
    if basic_type == lldb.eBasicTypeBool:
        return pwndbg.dbg_mod.TypeCode.BOOL

    f = type.GetTypeFlags()
    if f & lldb.eTypeIsInteger != 0:
        return pwndbg.dbg_mod.TypeCode.INT

    raise RuntimeError("missing mapping for type code")


def _is_optimized_out(value: lldb.SBValue) -> bool:
    """
    Returns whether the given value is likely to have been optimized out.
    """

    # We use this rather hacky way to distinguish if expressions that
    # contain values that have been optimized out, from those that are truly
    # invalid.
    #
    # Obviously, this is a rather bad solution, and breaks if the version of
    # LLDB we're running under is not in English, or if this message gets
    # changed in the future.
    #
    # LLDB does internally have a way to distinguish the invalid expression
    # case from the optimized-out one, through lldb::ExpressionResults, but
    # there does not seem to be a way to wrangle one out of
    # EvaluateExpression.
    #
    # In case this fails, we fall back to treating expression containing
    # optimized-out values the same way we treat invalid expressions, which
    # shoulnd't really be that bad.
    return value.error.description and "optimized out" in value.error.description


class LLDBType(pwndbg.dbg_mod.Type):
    inner: lldb.SBType

    def __init__(self, inner: lldb.SBType):
        self.inner = inner

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, LLDBType), "tried to compare LLDBType to other type"
        other: LLDBType = rhs

        return self.inner == other.inner

    @property
    @override
    def name_identifier(self) -> str | None:
        if self.inner.IsAnonymousType():
            return None
        return self.inner.name

    @property
    @override
    def name_to_human_readable(self) -> str:
        return self.inner.name

    @property
    @override
    def sizeof(self) -> int:
        return self.inner.GetByteSize()

    @property
    @override
    def alignof(self) -> int:
        # For some reason, GetByteAlign is only available from LLDB 19.1 [1]. So
        # if we're in an older version, we just assume it's naturally aligned.
        if LLDB_VERSION[0] >= 20 or (LLDB_VERSION[0] == 19 and LLDB_VERSION[1] >= 1):
            return self.inner.GetByteAlign()
        return self.sizeof

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        try:
            return map_type_code(self.inner)
        except Exception:
            # TODO: log invalid types
            return pwndbg.dbg_mod.TypeCode.INVALID

    @override
    def func_arguments(self) -> list[pwndbg.dbg_mod.Type] | None:
        if self.code != pwndbg.dbg_mod.TypeCode.FUNC:
            raise TypeError("only available for function type")

        args: list[lldb.SBType] = self.inner.GetFunctionArgumentTypes()
        if not args:
            return []
        return [LLDBType(arg) for arg in args]

    @override
    def fields(self) -> list[pwndbg.dbg_mod.TypeField]:
        if self.code == pwndbg.dbg_mod.TypeCode.ENUM:
            fields_enum: list[lldb.SBTypeEnumMember] = self.inner.get_enum_members_array()
            if not fields_enum:
                return []
            return [
                pwndbg.dbg_mod.TypeField(
                    0,
                    field.name,
                    LLDBType(field.type),
                    self,
                    field.signed,
                    False,
                    False,
                    0,
                )
                for field in fields_enum
            ]

        fields: list[lldb.SBTypeMember] = self.inner.get_fields_array()
        if not fields:
            return []
        return [
            pwndbg.dbg_mod.TypeField(
                field.bit_offset,
                field.name,
                LLDBType(field.type),
                self,
                0,
                False,
                False,  # TODO: Handle base class members differently.
                (field.bitfield_bit_size if field.is_bitfield else field.type.GetByteSize()),
            )
            for field in fields
        ]

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        return LLDBType(self.inner.GetArrayType(count))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return LLDBType(self.inner.GetPointerType())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        t = self.inner
        while t.IsTypedefType():
            t = t.GetTypedefedType()

        return LLDBType(t)

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        t = self.inner.GetPointeeType()
        if not t.IsValid():
            t = self.inner.GetArrayElementType()
        if not t.IsValid():
            raise pwndbg.dbg_mod.Error("tried to get target type of non-pointer and non-array type")

        return LLDBType(t)


class LLDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: lldb.SBValue, proc: LLDBProcess):
        self.proc = proc
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        addr = self.inner.AddressOf()
        return LLDBValue(addr, self.proc) if addr.IsValid() else None

    @property
    @override
    def is_optimized_out(self) -> bool:
        return _is_optimized_out(self.inner)

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        assert not self.is_optimized_out, "tried to get type of optimized-out value"

        return LLDBType(self.inner.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        deref = self.inner.Dereference()

        ex = None
        ty: LLDBType = None
        if not deref.GetError().success:
            ex = pwndbg.dbg_mod.Error(
                f"could not dereference value: {deref.GetError().description}"
            )

            assert isinstance(self.type, LLDBType), "LLDBValue.type must be an instance of LLDBType"
            ty = self.type

            if self.inner.unsigned != 0 or not ty.inner.IsPointerType():
                raise ex

        # Some versions of LLDB (16) will refuse to dereference null pointers,
        # even if they're valid for the program we're debugging - eg. QEMU. This
        # means that we have to handle them ourselves. We manually try to read
        # the data, and build a new value based on what we've read, if we're
        # successful.
        if self.inner.unsigned == 0:
            try:
                b = self.proc.read_memory(0, self.inner.GetByteSize(), partial=False)
            except pwndbg.dbg_mod.Error:
                # Nope, we really can't read it.
                raise ex

            if len(b) > 0xFF:
                # SetDataWithOwnership() is limited to 255 bits.
                raise pwndbg.dbg_mod.Error(
                    f"could not dereference value: value at 0x0 is too large (is {len(b)} bytes, must be at most 255)"
                )

            d = lldb.SBData()
            e = lldb.SBError()
            d.SetDataWithOwnership(e, b, self.proc.process.GetByteOrder(), len(b))

            if not e.success:
                raise pwndbg.dbg_mod.Error(f"could not dereference value: {e.description}")

            deref = self.proc.target.CreateValueFromData("nullderef", d, ty.inner.GetPointeeType())
            if not deref.IsValid():
                raise pwndbg.dbg_mod.Error(
                    "could not dereference value: SBTarget::CreateValueFromData failed"
                )

        return LLDBValue(deref, self.proc)

    @override
    def string(self) -> str:
        if self.inner.type.IsArrayType():
            # Array types need to have their address taken in LLDB.
            addr = self.inner.AddressOf().unsigned
        else:
            addr = self.inner.unsigned

        error = lldb.SBError()

        # Read strings up to 4GB.
        last_str = None
        buf = 256
        for i in range(8, 33):  # log2(256) = 8, log2(4GB) = 32
            s = self.inner.process.ReadCStringFromMemory(addr, buf, error)
            if error.Fail():
                raise pwndbg.dbg_mod.Error(f"could not read value as string: {error.description}")
            if last_str is not None and len(s) == len(last_str):
                break
            last_str = s

            buf *= 2

        return last_str

    @override
    def value_to_human_readable(self) -> str:
        return str(self.inner)

    @override
    def fetch_lazy(self) -> None:
        # Not needed under LLDB.
        pass

    @override
    def __int__(self) -> int:
        # use unsigned in every pointer type
        if self.type.code == pwndbg.dbg_mod.TypeCode.POINTER:
            return self.inner.GetValueAsUnsigned()

        # Logic is copied from lldb.value(self.inner).__int__()
        is_num, is_sign = lldb.is_numeric_type(
            self.inner.GetType().GetCanonicalType().GetBasicType()
        )
        if is_num and not is_sign:
            return self.inner.GetValueAsUnsigned()
        return self.inner.GetValueAsSigned()

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        assert isinstance(type, LLDBType)
        type: LLDBType = type

        if type.code == pwndbg.dbg_mod.TypeCode.FUNC:
            raise pwndbg.dbg_mod.Error("Cast to function type is not allowed, use pointer")

        return LLDBValue(self.inner.Cast(type.inner), self.proc)

    def _self_add_sub_int(self, val: int) -> pwndbg.dbg_mod.Value:
        """
        Adds the given signed integer to this value.
        """

        # Eventually we'll want to expand this, but currently we only use this
        # functionality for pointer arithmetic.
        if not self.inner.TypeIsPointerType():
            raise NotImplementedError(
                "Addition and subtraction to LLDBValue is only implemented for pointers"
            )

        ptrval = self.inner.unsigned
        elmlen = self.inner.type.size

        ptrval += elmlen * val

        return self.proc.create_value(ptrval).cast(self.type)

    @override
    def __add__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        return self._self_add_sub_int(rhs)

    @override
    def __sub__(self, rhs: int) -> pwndbg.dbg_mod.Value:
        return self._self_add_sub_int(-rhs)

    @override
    def __getitem__(self, key: str | int) -> pwndbg.dbg_mod.Value:
        if isinstance(key, str):
            value = self.inner.GetChildMemberWithName(key)
        elif isinstance(key, int):
            c = self.inner.GetType().GetTypeClass()
            if c == lldb.eTypeClassPointer:
                # GetChildAtIndex() at most only lets us dereference the pointer
                # at its original location, meaning that, to implement the
                # *(ptr+idx) behavior outlined in the Debugger-agnostic API, we
                # have to do the offset manually.
                offset_gen = self + key
                assert isinstance(offset_gen, LLDBValue)
                offset: LLDBValue = offset_gen

                value = offset.inner.Dereference()
            else:
                value = self.inner.GetChildAtIndex(key)

        if not value.IsValid():
            raise pwndbg.dbg_mod.Error(
                f"cannot get value with key '{key}': {value.error.description}"
            )

        return LLDBValue(value, self.proc)


class LLDBMemoryMap(pwndbg.dbg_mod.MemoryMap):
    def __init__(self, pages: list[pwndbg.lib.memory.Page]):
        super().__init__(pages)

    @override
    def is_qemu(self) -> bool:
        # TODO/FIXME: Figure a way to detect QEMU later.
        return False


class LLDBStopPoint(pwndbg.dbg_mod.StopPoint):
    inner: lldb.SBBreakpoint | lldb.SBWatchpoint
    proc: LLDBProcess
    stop_handler_name: str | None

    def __init__(
        self,
        inner: lldb.SBBreakpoint | lldb.SBWatchpoint,
        proc: LLDBProcess,
        stop_handler_name: str | None,
    ):
        self.inner = inner
        self.proc = proc
        self.stop_handler_name = stop_handler_name

    @override
    def remove(self) -> None:
        if isinstance(self.inner, lldb.SBBreakpoint):
            self.proc.target.BreakpointDelete(self.inner.id)
        elif isinstance(self.inner, lldb.SBWatchpoint):
            self.proc.target.DeleteWatchpoint(self.inner.GetID())

        # Remove the stop handler from the root module, as it's not needed
        # anymore.
        if self.stop_handler_name is not None:
            del sys.modules[self.proc.dbg.module].__dict__[self.stop_handler_name]

    @override
    def set_enabled(self, enabled: bool) -> None:
        self.inner.SetEnabled(enabled)


class OneShotAwaitable:
    """
    Used as part of the logic for the execution controller. This is an Awaitable
    object that yields the value passed to its constructor exactly once.
    """

    def __init__(self, value: Any):
        self.value = value

    def __await__(self) -> Generator[Any, Any, Any]:
        return (yield self.value)


class YieldContinue:
    """
    Continues execution of the process until the breakpoint or watchpoint given
    in the constructor is hit or the operation is cancelled.

    This class is part of the execution controller system, so it is intented to
    be yielded by the async function with access to an execution controller, and
    caught and hanlded by the event loop in the LLDB Pwndbg CLI.
    """

    target: LLDBStopPoint
    selected_thread: bool

    def __init__(self, target: LLDBStopPoint, selected_thread: bool = False):
        self.target = target
        self.selected_thread = selected_thread


class YieldSingleStep:
    """
    Moves execution of the process being debugged forward by one instruction.

    This class is part of the execution controller system, so it is intented to
    be yielded by the async function with access to an execution controller, and
    caught and hanlded by the event loop in the LLDB Pwndbg CLI.
    """


class LLDBExecutionController(pwndbg.dbg_mod.ExecutionController):
    @override
    def single_step(self) -> Awaitable[None]:
        return OneShotAwaitable(YieldSingleStep())

    @override
    def cont(self, target: pwndbg.dbg_mod.StopPoint) -> Awaitable[None]:
        assert isinstance(target, LLDBStopPoint)
        return OneShotAwaitable(YieldContinue(target))

    @override
    def cont_selected_thread(self, target: pwndbg.dbg_mod.StopPoint) -> Awaitable[None]:
        assert isinstance(target, LLDBStopPoint)
        return OneShotAwaitable(YieldContinue(target, selected_thread=True))


# Our execution controller doesn't need to change between uses, as all the state
# associated with it resides further up, in the Pwndbg CLI, so we can just share
# the same instance for all our uses.
EXECUTION_CONTROLLER = LLDBExecutionController()


class LLDBProcess(pwndbg.dbg_mod.Process):
    # Whether this process is based on `ProcessGDBRemote` (AKA: the `gdb-remote`
    # LLDB process plugin). This is used to selectively enable the functions
    # that interface with the remote GDB protocol.
    _is_gdb_remote: bool

    # The series number of the created value.
    _created_value_serial: int

    def __init__(
        self,
        dbg: LLDB,
        process: lldb.SBProcess,
        target: lldb.SBTarget,
        is_gdb_remote: bool,
    ):
        self.dbg = dbg
        self.process = process
        self.target = target
        self._is_gdb_remote = is_gdb_remote
        self._created_value_serial = 0

    @override
    def threads(self) -> list[pwndbg.dbg_mod.Thread]:
        return [
            LLDBThread(self.process.GetThreadAtIndex(i), self)
            for i in range(self.process.GetNumThreads())
        ]

    @override
    def pid(self) -> int | None:
        return self.process.GetProcessID() if self.alive() else None

    @override
    def alive(self) -> bool:
        return (
            self.process.GetState() != lldb.eStateExited
            and self.process.GetState() != lldb.eStateDetached
        )

    @override
    def is_core_file(self) -> bool:
        return bool(self.process.GetCoreFile().IsValid())

    @override
    def stopped_with_signal(self) -> bool:
        return self.process.GetState() == lldb.eStateStopped and any(
            thread.GetStopReason() == lldb.eStopReasonSignal for thread in self.process.threads
        )

    @override
    def stopped_at_breakpoint(self) -> bool:
        return self.process.GetState() == lldb.eStateStopped and any(
            thread.GetStopReason() == lldb.eStopReasonBreakpoint for thread in self.process.threads
        )

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        value = self.target.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value, self)

    def get_known_pages(self) -> list[pwndbg.lib.memory.Page]:
        import pwndbg.aglib

        regions = self.process.GetMemoryRegions()

        pages = []
        ranges: list[int] = []
        lens: list[int] = []

        for i in range(regions.GetSize()):
            region = lldb.SBMemoryRegionInfo()
            assert regions.GetMemoryRegionAtIndex(i, region), (
                "invalid region despite being in bounds"
            )

            start = region.GetRegionBase()
            size = region.GetRegionEnd() - start

            objfile = region.GetName()
            if objfile is None:
                # LLDB will sometimes give us overlapping ranges with no name.
                # For now, we ignore them, since GDB does not show them.
                ri = bisect.bisect_right(ranges, start)
                lb = (ranges[ri - i], lens[ri - 1]) if ri > 0 else None
                rb = (ranges[ri], lens[ri]) if ri < len(ranges) else None

                lbm = lb[0] + lb[1] > start if lb is not None else False
                rbm = start + size > rb[0] if rb is not None else False
                if lbm or rbm:
                    continue

                # Try to resolve the name anyway by using SBAddress.
                file = lldb.SBAddress(region.GetRegionBase(), self.target).GetModule().GetFileSpec()
                objfile = file.fullpath if file.IsValid() else f"[anon_{start >> 12:05x}]"

            perms = 0
            if region.IsReadable():
                perms |= os.R_OK
            if region.IsWritable():
                perms |= os.W_OK
            if region.IsExecutable():
                perms |= os.X_OK

            # LLDB doesn't actually tell us the offset of a mapped file.
            offset = 0

            # Add this range to our range map.
            #
            # Currently this is O(n) on the number of pages. It could be faster,
            # if we had some sort of BTreeMap-like structure in Python, but we
            # don't, and that would need an external dependency afaict, so we
            # do this for now.
            #
            # TODO: Use a sorted map for overlapping memory range detection.
            ri = bisect.bisect_left(ranges, start)
            ranges.insert(ri, start)
            lens.insert(ri, size)

            # Add the page to our returned list.
            pages.append(
                pwndbg.lib.memory.Page(
                    start=region.GetRegionBase(),
                    size=region.GetRegionEnd() - region.GetRegionBase(),
                    flags=perms,
                    offset=offset,
                    arch_ptrsize=pwndbg.aglib.arch.ptrsize,
                    objfile=objfile,
                )
            )

        return pages

    def _process_vmmap_pages(
        self, pages: list[pwndbg.lib.memory.Page]
    ) -> list[pwndbg.lib.memory.Page]:
        import pwndbg.aglib
        import pwndbg.lib.memory

        # Do a final, coalescing pass, for identical ranges that are sequential
        # and contiguous to each other in the virtual address space, and join
        # them into a single range.
        #
        # LLDB - particularly in macOS - may yield multiple ranges that describe
        # contiguous sequential regions of virtual memory, but are otherwise
        # identical. This seems to happen because LLDB internally distinguishes
        # between different Mach-O sections. That information, however, is not
        # made reliably available to us.
        ptrsize: int = pwndbg.aglib.arch.ptrsize
        final_pages: list[pwndbg.lib.memory.Page] = []
        start = None
        end = None
        for page in pages:
            if start is None:
                start = page
                continue

            target = end if end is not None else start
            otherwise_equal = (
                target.flags == page.flags
                and target.objfile == page.objfile
                and target.in_darwin_shared_cache == page.in_darwin_shared_cache
            )

            if target.end == page.start and otherwise_equal:
                end = page
            else:
                final_pages.append(
                    pwndbg.lib.memory.Page(
                        start.start,
                        target.end - start.start,
                        start.flags,
                        start.offset,
                        ptrsize,
                        start.objfile,
                        start.in_darwin_shared_cache,
                    )
                )
                start = page
                end = None

        if start is not None:
            final_pages.append(start)

        return final_pages

    @override
    def vmmap(self) -> pwndbg.dbg_mod.MemoryMap:
        from pwndbg.aglib.commpage import get_commpage_mappings

        pages = self.get_known_pages()
        if pages:
            pages.extend(get_commpage_mappings())
            pages.sort()

            return LLDBMemoryMap(self._process_vmmap_pages(pages))

        from pwndbg.aglib.kernel.vmmap import kernel_vmmap
        from pwndbg.aglib.vmmap_custom import get_custom_pages

        pages: list[pwndbg.lib.memory.Page] = []
        pages.extend(kernel_vmmap())
        pages.extend(get_custom_pages())
        pages.sort()

        return LLDBMemoryMap(self._process_vmmap_pages(pages))

    def find_largest_range_len(
        self, min_search: int, max_search: int, test: Callable[[int], bool]
    ) -> int:
        """
        Finds the largest memory range given a minimum and a maximum value
        for the size of the rage. This is a binary search, so it should do on
        the order of log2(max_search - min_search) attempts before it arrives at
        an answer.
        """
        # See if there's even any region we could possibly read.
        r = max_search - min_search
        if r == 0:
            return min_search if test(min_search) else 0

        # Pick the midpoint from our previous search.
        mid_search = min_search + r // 2

        if not test(mid_search):
            # No dice. This means the limit of the mapping must come before the
            # midpoint.
            return self.find_largest_range_len(min_search, mid_search, test)

        # We can read this range. This means that the limit of the mapping must
        # come after the midpoint, or be equal to it, exactly.
        after = self.find_largest_range_len(mid_search + 1, max_search, test)
        if after > 0:
            # It came after the midpoint.
            return after

        # We are exactly at the limit.
        return min_search

    @override
    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        if size == 0:
            return bytearray()

        # Try to read exactly the requested size.
        e = lldb.SBError()
        buffer = self.process.ReadMemory(address, size, e)
        if buffer:
            return bytearray(buffer)
        if not partial:
            raise pwndbg.dbg_mod.Error(f"could not read {size:#x} bytes: {e}")

        # At this point, we're in a bit of a pickle. LLDB doesn't give us enough
        # information to find out what the last address it can read from is. For
        # all we know, it could be any address in the range (address, address+size),
        # so we have to get creative.
        #
        # First, try to derive that information from the mmap.
        #
        # TODO: Finding the first range in the memory map could be done using a
        # binary search, so we should do that eventually.
        first_page = None
        last_page = None
        vmmap_size = 0

        # Use the aglib version of the vmmap, as it is cached, and `vmmap()` may
        # be very slow on some targets.
        for page in pwndbg.aglib.vmmap.get():
            if address in page and not first_page:
                first_page = page
                last_page = page
                vmmap_size = page.memsz - (address - page.start)
            elif last_page:
                assert last_page.end <= page.start, (
                    "memory map regions should be sorted and not overlap at this point"
                )

                if page.start == last_page.end:
                    last_page = page
                    vmmap_size += page.memsz
                else:
                    break

        if vmmap_size > 0:
            try:
                return self.read_memory(address, vmmap_size, partial=False)
            except pwndbg.dbg_mod.Error:
                # Unreliable memory map?
                pass

        # Second, try to do a binary search for the limit of the range.
        def test(s: int):
            # ReadMemory fail when passing size <= 0
            if s <= 0:
                return False

            b = self.process.ReadMemory(address, s, e)
            return b is not None

        size = self.find_largest_range_len(0, size, test)
        if size > 0:
            return bytearray(self.process.ReadMemory(address, size, e))
        return bytearray()

    @override
    def write_memory(self, address: int, data: bytearray, partial: bool = False) -> int:
        if len(data) == 0:
            return 0

        e = lldb.SBError()
        count = self.process.WriteMemory(address, data, e)
        if (count < len(data) or not e.success) and not partial:
            raise pwndbg.dbg_mod.Error(f"could not write {len(data)} bytes: {e}")

        # In some instances - eg. writing to the PC - writing may still have
        # failed when we get here. Make sure we can read it back, to a point.
        readback_len = min(len(data), 64)
        if self.read_memory(address, readback_len) != data[:readback_len]:
            raise pwndbg.dbg_mod.Error(f"could not write {len(data)} bytes: read-back failed")

        # We know some memory got changed.
        self.dbg._trigger_event(pwndbg.dbg_mod.EventType.MEMORY_CHANGED)
        return count

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

        # LLDB 19.1 and greater has a FindRangesInMemory function[1], but, as of
        # the writing of this comment, that verson is still in RC1 stage, so new
        # that it is not reasonable for us to depend on that function being
        # available. So what we do here is mostly the same search procedure
        # done by LLDB, but much slower on account of FFI and Python.
        #
        # This really is not ideal for large ranges and smaller alignments.
        #
        # [1]: https://github.com/llvm/llvm-project/commit/0d4da0df166ea7512c6e97e182b21cd706293eaa

        offset = start - pwndbg.lib.memory.round_up(start, align)
        moffset = 0
        matched = 0
        yielded = 0

        e = lldb.SBError()
        while offset < size and (max_matches < 0 or yielded < max_matches):
            # Because we would reject any match that is not correctly aligned
            # anyway, we can perform the search in alignment-sized chunks,
            # rather than one byte at a time. This is a nice little optimization
            # that allows us to cut the number of iterations by a factor of
            # `align`. Additionally, we can read only as much as we'd need to
            # complete the match if that is smaller than the alignment.
            to_read = min(len(pattern) - matched, align)
            if to_read > size - offset:
                # Even if we found a match here, part of it would be outside the
                # range specified for the search, and we should not yield it.
                break

            read = self.process.ReadMemory(start + offset, to_read, e)
            offset += align

            if e.success:
                if pattern[matched : matched + len(read)] == read:
                    # This part of the slice matches the continuation of the
                    # pattern.
                    matched += len(read)
                elif pattern[: len(read)] == read:
                    # The pattern may start in the slice we reject, so we have
                    # to account for that.
                    offset -= align
                    moffset = offset
                    matched = 0
                else:
                    # This part of the slice doesn't match the continuation of
                    # the pattern. Restart the match.
                    moffset = offset
                    matched = 0

                if matched == len(pattern):
                    # We have a complete sequence. Yield the address at which it
                    # was found.
                    yield start + moffset
                    yielded += 1

                    if step > 0:
                        # Step on success if a step amount was given.
                        offset -= align
                        offset = pwndbg.lib.memory.round_up(
                            pwndbg.lib.memory.round_down(offset, step) + step, align
                        )

                    moffset = offset
                    matched = 0
            else:
                # We couldn't read this slice, move on.
                moffset = offset
                matched = 0

    @override
    def is_remote(self) -> bool:
        # The REPL knows when a remote target has been connected to, or when a
        # local process has been launched. So we let it take the reigns and just
        # relay that information to the rest of Pwndbg.
        return self._is_gdb_remote

    @override
    def send_remote(self, packet: str) -> bytes:
        if len(packet) == 0:
            raise pwndbg.dbg_mod.Error("Empty packets are not allowed")
        if not self._is_gdb_remote:
            raise RuntimeError("Called send_remote() on a local process")

        # As of LLDB 18, there isn't a way for us to do this directly, so we
        # have to use the command. The implementation of the command calls into
        # private APIs.

        # FIXME: `plugin packet send` Don't handle well bytes or nullbytes, because they use `%s` in lldb[1]
        # [1] https://github.com/llvm/llvm-project/blob/6c42d0d7df55f28084e41b482dd7c25d4e7bcd10/lldb/source/Plugins/Process/gdb-remote/ProcessGDBRemote.cpp#L5660
        response = self.dbg._execute_lldb_command(f"process plugin packet send {packet}")

        try:
            idx = response.index("\nresponse: ")
        except ValueError:
            # Packets not implemented return empty
            return b""

        out = response[idx + 11 :]  # len("\nresponse: ") == 11
        if out.startswith("\nerror: "):
            # Packets not implemented return empty
            return b""

        if out[-1] == "\n":
            out = out[:-1]

        return out.encode()

    @override
    def send_monitor(self, cmd: str) -> str:
        if len(cmd) == 0:
            raise pwndbg.dbg_mod.Error("Empty monitor commands are not allowed")
        if not self._is_gdb_remote:
            raise RuntimeError("Called send_monitor() on a local process")

        # `process plugin packet monitor {cmd}` command is returned in an ugly way, eg:
        # "Host virtual address for 0x1000 (virt.flash0) is 0xe2780fc01000\r\n  packet: qRcmd,6770613268766120307831303030\nresponse: OK\n"
        # We need to cut the string, so it matches the same format we have in GDB.

        res = self.dbg._execute_lldb_command(f"process plugin packet monitor {cmd}")
        if (idx := res.rindex("  packet: ")) > -1:
            return res[:idx]
        return res

    @override
    def download_remote_file(self, remote_path: str, local_path: str) -> None:
        if not self._is_gdb_remote:
            raise RuntimeError("Called send_monitor() on a local process")

        # Ideally, we'd try using the F remote packet family[1] first, as those
        # are guaranteed to go to the remote process. Before trying to pull
        # the remote file from the LLDB remote platform.
        #
        # TODO: Add a File I/O Remote Protocol Extension interface to LLDB.download_remote_file.
        #
        # [1]: https://sourceware.org/gdb/current/onlinedocs/gdb.html/File_002dI_002fO-Remote-Protocol-Extension.html

        # This depends on the user setting the platform correctly. In LLDB,
        # a remote platform is distinct from a remote process, and retrieving
        # files from the remote host is squarely the job of the remote platform.
        # This can become a bit of a problem when the user sets up the remote
        # process correctly, but not the remote platform.
        #
        # This is generally harmless when the host and remote systems don't
        # share a readable file under the same path. But when that is the case,
        # LLDB's remote platform system will happily answer our request, and we
        # won't be able to tell it did anything wrong.
        #
        # We mitigate this by showing a warning[2] to the user when they connect
        # to a remote process while keeping the host platform, but we can't do
        # much beyond that at this point.
        #
        # [2]: See `pwndbg.dbg_mod.lldb.repl.process_connect`.
        platform = self.target.GetPlatform()

        remote = lldb.SBFileSpec(remote_path)
        local = lldb.SBFileSpec(local_path)

        if not platform.IsValid():
            raise pwndbg.dbg_mod.Error("no remote platform we can use")

        if not remote.IsValid():
            raise pwndbg.dbg_mod.Error(f"LLDB considers the path '{remote_path}' invalid")
        if not local.IsValid():
            raise pwndbg.dbg_mod.Error(f"LLDB considers the path '{local_path} invalid'")

        error = platform.Get(remote, local)
        if not error.success:
            raise pwndbg.dbg_mod.Error(
                f"could not get remote file {remote_path}: {error.description}"
            )

    @override
    def create_value(
        self, value: int, type: pwndbg.dbg_mod.Type | None = None
    ) -> pwndbg.dbg_mod.Value:
        import struct

        b = struct.pack("<Q", value)

        e = lldb.SBError()
        data = lldb.SBData()
        data.SetDataWithOwnership(e, b, lldb.eByteOrderLittle, len(b))

        import pwndbg.aglib.typeinfo

        u64 = pwndbg.aglib.typeinfo.uint64

        assert u64, "aglib.typeinfo must have already been set up"
        assert isinstance(u64, LLDBType), "aglib.typeinfo contains non-LLDBType values"
        u64: LLDBType = u64

        series = self._created_value_serial
        self._created_value_serial += 1
        value = self.target.CreateValueFromData(f"$PWNDBG_CREATED_VALUE_{series}", data, u64.inner)
        value = LLDBValue(value, self)

        if type:
            return value.cast(type)
        return value

    @override
    def symbol_name_at_address(self, address: int) -> str | None:
        addr = lldb.SBAddress(address, self.target)

        # We are using `lldb.eSymbolContextEverything` because it can find symbols without debug info.
        # Additional information:
        # `eSymbolContextVariable` is potentially expensive to look up,
        # so it is not included in `eSymbolContextEverything`.
        ctx = self.target.ResolveSymbolContextForAddress(addr, lldb.eSymbolContextEverything)

        if not ctx.IsValid() or not ctx.symbol.IsValid():
            return None

        sym_addr = ctx.symbol.addr.GetLoadAddress(self.target)
        if sym_addr == lldb.LLDB_INVALID_ADDRESS:
            # Unlikely. LLDB can return some truly insane matches sometimes. In
            # this case, we could not find the load address of the symbol we
            # matched. Act as if we found nothing.
            return None

        assert sym_addr <= address, (
            f"LLDB returned an out-of-range address {sym_addr:#x} for a requested symbol with address {address:#x}"
        )

        if sym_addr != address:
            # Print the symbol name along with an offset value if the address we
            # were given does not match up with the symbol exactly.
            sym_name = ctx.symbol.name
            if not ctx.symbol.name:
                return None

            return f"{sym_name}+{address - sym_addr}"

        return ctx.symbol.name

    def _resolve_tls_symbol(self, sym: lldb.SBSymbol) -> int | None:
        """
        Attemps to resolve the address of a symbol stored in TLS.
        """
        # Please read book: https://akkadia.org/drepper/tls.pdf
        #
        # LLDB doesn't handle symbols marked with STT_TLS at all[1][2], which
        # means that not only will they not have a type, they will also
        # give completely wrong results for GetStartAddress(), meaning we
        # can't use any of the mechanisms in LLDB to figure out where a TLS
        # symbol is located.
        #
        # Here, we try to resolve any symbols that don't have a type as TLS
        # symbols, and, if we're successful, we return what we got. This is
        # far from reliable, but it's the best we've got until LLDB gives us
        # a proper way to handle these symbols.
        #
        # Additionally, this is a Linux+Glibc-only workaround, for now.
        # We'll see. We should also consider parsing the symbols in the ELF
        # file associated with the module LLDB found the symbol in, to check
        # for whether this is a TLS symbol.
        #
        # I wish we didn't have to do this at all, but `pwndbg.aglib.heap`
        # needs TLS symbols to work and I want at least _some_ level of support
        # for it in LLDB :(
        #
        # [1]: https://github.com/llvm/llvm-project/blob/86cf67ffc1ee62c65bef313bf58ae70f74afb7c1/lldb/source/Plugins/ObjectFile/ELF/ObjectFileELF.cpp#L2140
        # [2]: https://github.com/llvm/llvm-project/issues/178953
        import pwndbg.aglib.tls
        import pwndbg.libc

        if not (self.is_linux() and pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC):
            print(
                f"warning: symbol '{sym.GetName()}' might be a TLS symbol, but Pwndbg only knows how to resolve those in x86-64 GNU/Linux"
            )
            return None

        tls_base = (
            pwndbg.aglib.tls.find_address_with_register()
            or pwndbg.aglib.tls.find_address_with_pthread_self()
        )
        if tls_base == 0:
            print(
                f"warning: symbol '{sym.GetName()}' might be a TLS symbol, but the TCB for the current thread could not be found"
            )
            return None

        # `tls_base` should now point to a `tcbhead_t` structure, as defined in
        # [1]. We want to scan through `dtv` until we hit the first element with
        # which we can construct an address value of the form
        # `dtv[i].pointer.val + sym.GetValue()` which is readable by us. The
        # entries in `dtv` are defined in [2]. We scan only as many as
        # `self.target.GetNumModules() + 1` entries.
        #
        # [1]: https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/sysdeps/x86_64/nptl/tls.h#L70
        # [2]: https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/sysdeps/generic/dl-dtv.h#L33
        offset = sym.GetValue()
        import pwndbg.aglib.memory

        try:
            tls_base_typed = pwndbg.aglib.memory.get_typed_pointer("typedef tcbhead_t", tls_base)
        except TypeNotFoundError:
            # We get a TypeNotFoundError here if glibc does not have debug info.
            return None

        for module_id in range(self.target.GetNumModules() + 1):
            # This is the same as `tls_base->dtv[module_id].pointer.val + offset`.
            candidate = int(tls_base_typed["dtv"][module_id]["pointer"]["val"]) + offset
            if pwndbg.aglib.memory.peek(candidate):
                # Take a guess that we hit the right TLS block and return what
                # we got.
                return candidate

        print(
            f"warning: symbol '{sym.GetName()}' might be a TLS symbol, but it could not be resolved"
        )
        return None

    @override
    def lookup_symbol(
        self,
        name: str,
        *,
        prefer_static: bool = False,
        type: pwndbg.dbg_mod.SymbolLookupType = pwndbg.dbg_mod.SymbolLookupType.ANY,
        objfile_endswith: str | None = None,
    ) -> pwndbg.dbg_mod.Value | None:
        objfile: lldb.SBModule | None = None
        if objfile_endswith is not None:
            for m in self.target.module_iter():
                # FIXME: Path().resolve() is a workaround for #3641
                if str(Path(m.file.fullpath).resolve()).endswith(objfile_endswith):
                    objfile = m
                    break
            if objfile is None:
                raise pwndbg.dbg_mod.Error(f"Objfile '{objfile_endswith}' not found")

        symbol_for_preference = None
        for sym, cast_type, resolved_addr in self._iter_symbols(name, type, objfile):
            is_static = not sym.IsExternal()
            if prefer_static == is_static:
                symbol_for_preference = sym, cast_type, resolved_addr
                break

            if symbol_for_preference is None:
                symbol_for_preference = sym, cast_type, resolved_addr

        if symbol_for_preference is None:
            return None

        sym, cast_type, resolved_addr = symbol_for_preference
        return self.create_value(resolved_addr, cast_type)

    @override
    def get_function_boundaries(self, address: int) -> tuple[int, int] | None:
        addr = self.target.ResolveLoadAddress(address)

        if not addr.IsValid():
            return None

        func = addr.GetFunction()
        if func.IsValid():
            start: int = func.GetStartAddress().GetLoadAddress(self.target)
            end: int = func.GetEndAddress().GetLoadAddress(self.target)
            return start, end

        return None

    def _iter_symbols(
        self,
        name: str,
        type: pwndbg.dbg_mod.SymbolLookupType,
        objfile: lldb.SBModule | None = None,
    ) -> Iterator[tuple[lldb.SBSymbol, pwndbg.dbg_mod.Type, int]]:
        # Info from commit: https://github.com/llvm/llvm-project/commit/bcf2cfbdc5f7b8998d1a06e2e4b640dd42a5b10f
        # eSymbolTypeFunction: eSymbolTypeCode with IsDebug() == true
        #   eSymbolTypeGlobal: eSymbolTypeData with IsDebug() == true and IsExternal() == true
        #   eSymbolTypeStatic: eSymbolTypeData with IsDebug() == true and IsExternal() == false
        #
        # Global Variables:
        # Use t.FindSymbols('main_arena', lldb.eSymbolTypeData)
        #
        # Global Functions:
        # Use t.FindSymbols('free', lldb.eSymbolTypeCode)
        #
        # Local Variables:
        # Directly finding local variables is not possible using t.FindSymbols
        #
        # Local/Global Variables, Functions, or Any Symbol:
        # Use pwndbg.dbg_mod.selected_frame().evaluate_expression('&result_local')
        # Note that this approach works for both local and global variables as well as functions.
        #
        # Note using `evaluate_expression` on TLS Variables:
        # TLS variables may not work on some architectures. For example, this approach
        # works fine on x86_64, but may fail on aarch64 or other architectures.

        # We need to map variable types to symbols...
        # This approach may not work correctly if there are multiple global variables with the same <name> and <address>.
        # The same address may occur for TLS symbols, as they have a `0xffffffffffffffff` address.
        # NOTE: `FindGlobalVariables` returns ONLY variables that have DEBUG INFO.
        variables_types: dict[tuple[int, str], LLDBType] = {}

        if type in (
            pwndbg.dbg_mod.SymbolLookupType.VARIABLE,
            pwndbg.dbg_mod.SymbolLookupType.ANY,
        ):
            variables: lldb.SBValueList
            if objfile:
                variables = objfile.FindGlobalVariables(self.target, name, 0)
            else:
                variables = self.target.FindGlobalVariables(name, 0)
            var: lldb.SBValue
            for var in variables:
                # LLDB[1] is attempting to resolve a TLS variable, but it fails with the following error:
                # [1] https://github.com/llvm/llvm-project/blob/1dfa34c8e1f28963f059e05ce89ebf1f76ebbddc/lldb/source/Expression/DWARFExpression.cpp#L2198
                #
                # is_tls = var.error and var.error.description == 'no thread to evaluate TLS within'

                # <address>, <variable_name>
                key = (int(var.GetLoadAddress()), var.GetName())
                variables_types[key] = LLDBType(var.GetType())

        domains = {
            pwndbg.dbg_mod.SymbolLookupType.ANY: (lldb.eSymbolTypeAny,),
            # TLS variables are included under `eSymbolTypeAny`, so we need to check
            pwndbg.dbg_mod.SymbolLookupType.VARIABLE: (
                lldb.eSymbolTypeData,
                lldb.eSymbolTypeAny,
            ),
            pwndbg.dbg_mod.SymbolLookupType.FUNCTION: (lldb.eSymbolTypeCode,),
        }[type]

        symbols_iter: Iterator[lldb.SBSymbolContextList] = (
            (objfile or self.target).FindSymbols(name, domain) for domain in domains
        )
        for symbols in symbols_iter:
            size = symbols.GetSize()
            if size == 0:
                continue

            for i in range(size):
                sym: lldb.SBSymbol = symbols.GetContextAtIndex(i).symbol
                if not sym:
                    continue

                if not sym.IsValid():
                    continue

                addr: lldb.SBAddress = sym.GetStartAddress()
                if not addr.IsValid():
                    continue

                resolved_addr = addr.GetLoadAddress(self.target)
                resolved_size = sym.GetSize()
                sym_name = sym.GetName()

                cast_type: pwndbg.dbg_mod.Type
                if addr.function.IsValid():
                    # is function
                    cast_type = LLDBType(addr.function.type).pointer()
                else:
                    # is variable maybe or others types

                    # LLDB lacks support for types in symbols
                    # So we have manually find types
                    cast_type = variables_types.get((resolved_addr, sym_name))
                    if cast_type is not None:
                        # Detect if we have proper symbol by size, we can't do better here
                        if cast_type.sizeof != resolved_size:
                            print(
                                message.warn(
                                    f"WARNING: Symbol {sym_name} has invalid size (has:{cast_type.sizeof:02x}, needed:{resolved_size:02x}), should not happen"
                                )
                            )

                        # Cast to pointer, we are returning address at end ;)
                        cast_type = cast_type.pointer()
                    else:
                        # Address without/unknown type, we cast to void pointer
                        # This happens eg:
                        # - when function don't have debug info
                        # - variable has missing debug info
                        # TODO: Should we create a 'pvoidfunc' type.
                        #   This could be useful for identifying functions without debug info.
                        cast_type = pwndbg.aglib.typeinfo.pvoid

                sym_type = sym.GetType()
                if addr.section.name in (".tbss", ".tdata") and sym_type == lldb.eSymbolTypeInvalid:
                    # Additionally, we check only TLS sections (.tbss and .tdata).
                    # Symbols with type eSymbolTypeInvalid might represent TLS symbols.
                    # Attempt to resolve this symbol and verify if it provides a valid result.
                    tls = self._resolve_tls_symbol(sym)
                    if tls:
                        yield sym, cast_type, tls
                    continue

                if resolved_addr == lldb.LLDB_INVALID_ADDRESS:
                    continue

                yield sym, cast_type, resolved_addr

    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        types = self.target.FindTypes(name)
        return [LLDBType(types.GetTypeAtIndex(i)) for i in range(types.GetSize())]

    @override
    def arch(self) -> ArchDefinition:
        endian0 = self.process.GetByteOrder()
        endian1 = self.target.GetByteOrder()

        # Sometimes - particularly when using `gdb-remote` - the process might not have had
        # its architecture, and thus its byte order, properly resolved. This happens often
        # around architectures like MIPS. In those cases, we might have some luck falling
        # back to the architecture information in the target, that might've been manually
        # set by the user, or properly detected during target creation.
        if endian0 == lldb.eByteOrderInvalid:
            endian0 = endian1

        if endian0 != endian1:
            raise RuntimeError(
                "SBTarget::GetByteOrder() != SBProcess::GetByteOrder(). We don't know how to handle that"
            )
        if endian0 not in (lldb.eByteOrderLittle, lldb.eByteOrderBig):
            raise RuntimeError("We only support little and big endian systems")
        if endian0 == lldb.eByteOrderInvalid:
            raise RuntimeError("Byte order is invalid")

        endian: Literal["little", "big"] = "little" if endian0 == lldb.eByteOrderLittle else "big"

        ptrsize0 = self.process.GetAddressByteSize()
        ptrsize1 = self.target.GetAddressByteSize()
        if ptrsize0 != ptrsize1:
            raise RuntimeError(
                "SBTarget::GetAddressByteSize() != SBProcess::GetAddressByteSize(). We don't know how to handle that"
            )

        names = self.target.GetTriple().split("-")
        if len(names) == 0 or len(names[0]) == 0:
            # This is a scary situation to be in. LLDB lets users attatch to
            # processes even when it has no idea what the target is. In those
            # cases, the target triple name will be missing, and pretty much
            # every other piece of information coming from LLDB will be
            # unreliable.
            #
            # We should have to handle ourselves gracefully here, but there's
            # basically nothing we can do to help with this, so we error out.
            raise pwndbg.dbg_mod.Error("Unknown target architecture")

        arch_name = names[0]
        if arch_name == "x86_64":
            # GDB and Pwndbg use a different name for x86_64.
            arch_name = "x86-64"
        elif arch_name == "arm":
            # LLDB doesn't distinguish between ARM Cortex-M and other varieties
            # of ARM. Pwndbg needs that distinction, so we attempt to detect
            # Cortex-M varieties by querying for the presence of the `xpsr`
            # register.
            def _has_xpsr(thread) -> bool:
                with thread.bottom_frame() as frame:
                    return frame.regs().by_name("xpsr") is not None

            has_xpsr = [_has_xpsr(thread) for thread in self.threads()]
            assert all(has_xpsr) or not any(has_xpsr), (
                "Either all threads are Cortex-M or none are, Pwndbg doesn't know how to handle other cases"
            )

            if any(has_xpsr):
                arch_name = "armcm"
        elif arch_name in {"arm64", "arm64e"}:
            # Apple uses a different name for AArch64 than we do.
            arch_name = "aarch64"
        elif arch_name == "riscv32":
            # Pwndbg use a different name for riscv32.
            arch_name = "rv32"
        elif arch_name == "riscv64":
            # Pwndbg use a different name for riscv64.
            arch_name = "rv64"
        elif arch_name in ("powerpc", "powerpc64le", "ppc64le"):
            arch_name = "powerpc"

        # Distinguish Apple platforms, default to Linux otherwise.
        if len(names) >= 2 and names[1] == "apple":
            platform = Platform.DARWIN
        else:
            platform = Platform.LINUX

        return ArchDefinition(name=arch_name, ptrsize=ptrsize0, endian=endian, platform=platform)

    @override
    def break_at(
        self,
        location: pwndbg.dbg_mod.BreakpointLocation | pwndbg.dbg_mod.WatchpointLocation,
        stop_handler: Callable[[pwndbg.dbg_mod.StopPoint], bool] | None = None,
        internal: bool = False,
    ) -> pwndbg.dbg_mod.StopPoint:
        if isinstance(location, pwndbg.dbg_mod.BreakpointLocation):
            e = None
            bp = self.target.BreakpointCreateByAddress(location.address)
        elif isinstance(location, pwndbg.dbg_mod.WatchpointLocation):
            e = lldb.SBError()
            bp = self.target.WatchAddress(
                location.address,
                location.size,
                location.watch_read,
                location.watch_write,
                e,
            )

        if not bp.IsValid():
            raise pwndbg.dbg_mod.Error(
                f"could not create breakpoint/watchpoint: {e.description if e else 'unknown error'}"
            )

        # If we have a stop handler, pick a name for it.
        #
        # As with `add_command`, LLDB will not accept a direct handle to a
        # class or function, and, instead, expects its name, in a way that it
        # can access. In the same way as we do in `add_command`, we register
        # our handler in the scope of the module we load in LLDB.
        #
        # Additionally, because the handler function is anonymous, we pick a
        # randomized name for it.
        stop_handler_name = None
        if stop_handler is not None:
            while True:
                rand = round(random.random() * 0xFFFFFFFF) // 1
                rand = f"{rand:08x}"
                stop_handler_name = f"__{rand}_LLDB_BREAKPOINT_STOP_HANDLER"

                if stop_handler_name not in sys.modules[self.dbg.module].__dict__:
                    break

        # Create the stop point handle.
        sp = LLDBStopPoint(bp, self, stop_handler_name)

        # And, now that we have the stop point handle, create and register the
        # LLDB stop handler for the breakpoint, then register it. We can't
        # create it earlier, since the handler takes the stop point handle as
        # its first argument.
        if stop_handler is not None:

            def handler(
                _frame: lldb.SBFrame,
                _bp_loc: lldb.SBBreakpointLocation,
                _struct: lldb.SBStructuredData,
                _internal,
            ) -> bool:
                try:
                    self.dbg.lldb_python_state_callback(LLDBPythonState.LLDB_STOP_HANDLER)
                    return stop_handler(sp)
                finally:
                    self.dbg.lldb_python_state_callback(LLDBPythonState.PWNDBG)

            sys.modules[self.dbg.module].__dict__[stop_handler_name] = handler

            path = f"{self.dbg.module}.{stop_handler_name}"
            if isinstance(bp, lldb.SBBreakpoint):
                self.target.debugger.HandleCommand(f"breakpoint command add -F {path} {bp.id}")
            elif isinstance(bp, lldb.SBWatchpoint):
                self.target.debugger.HandleCommand(f"watchpoint command add -F {path} {bp.GetID()}")

        return sp

    @override
    def trace_ret(self, stop_handler: Callable[[], bool] | None = None, internal: bool = False):
        if stop_handler is None:

            def stop_handler():
                return True

        def new_stop_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
            return stop_handler()

        retaddr = pwndbg.dbg.selected_frame().parent().pc()
        bp = pwndbg.dbg_mod.BreakpointLocation(retaddr)
        self.break_at(bp, new_stop_handler, internal)

    @override
    def disasm(self, address: int) -> pwndbg.dbg_mod.DisassembledInstruction | None:
        instructions = self.target.ReadInstructions(lldb.SBAddress(address, self.target), 1)
        if not instructions.IsValid() or instructions.GetSize() == 0:
            return None

        instr: lldb.SBInstruction = instructions.GetInstructionAtIndex(0)
        mnemonic = instr.GetMnemonic(self.target)
        operands = instr.GetOperands(self.target)

        return {
            "addr": instr.GetAddress().GetLoadAddress(self.target),
            "asm": f"{mnemonic} {operands}",
            "length": instr.GetByteSize(),
        }

    @override
    def is_linux(self) -> bool:
        # LLDB will at most tell us if this is a SysV ABI process.
        # Returns eg:
        # - 'SysV-arm64'
        # - 'ABIMacOSX_arm64'
        return self.target.GetABIName().lower().startswith("sysv")

    @override
    def module_section_locations(self) -> list[tuple[int, int, str, str]]:
        result = []
        for i in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(i)

            queue = collections.deque(
                module.GetSectionAtIndex(j) for j in range(module.GetNumSections())
            )
            while len(queue) > 0:
                section = queue.popleft()
                children = section.GetNumSubSections()
                if children > 0:
                    queue.extendleft(section.GetSubSectionAtIndex(k) for k in range(children))
                    continue

                load = section.GetLoadAddress(self.target)
                if load == lldb.LLDB_INVALID_ADDRESS:
                    # This section is not loaded.
                    continue

                fullpath = pwndbg.lib.path.clean_path(str(module.GetFileSpec()))

                result.append((load, section.GetByteSize(), section.GetName(), fullpath))

        return result

    @override
    def main_module_name(self) -> str:
        spec = (
            self.target.GetModuleAtIndex(0).GetFileSpec()
            if self.target.GetNumModules() > 0
            else None
        )

        if spec is None:
            return None

        return pwndbg.lib.path.clean_path(str(spec))

    @override
    def main_module_entry(self) -> int | None:
        return (
            self.target.GetModuleAtIndex(0)
            .GetObjectFileEntryPointAddress()
            .GetLoadAddress(self.target)
            if self.target.GetNumModules() > 0
            else None
        )

    @override
    def is_dynamically_linked(self) -> bool:
        # This should more or less match the behavior of `info dll`, as descibed
        # in the docstring for this method. We assume that targets that have no
        # known modules - as is the case by default for QEMU - are statically
        # linked, same as GDB 13.2.
        nfile_backed = 0
        for i in range(self.target.GetNumModules()):
            module = self.target.GetModuleAtIndex(i)
            # We must check this so we don't count modules like [vdso] (#3643)
            if module.IsFileBacked():
                nfile_backed += 1
                if nfile_backed > 1:
                    return True

        return False

    @override
    def dispatch_execution_controller(
        self,
        procedure: Callable[[pwndbg.dbg_mod.ExecutionController], Coroutine[Any, Any, None]],
    ):
        # Queue the coroutine up for execution by the Pwndbg CLI.
        self.dbg.controllers.append((self, procedure(EXECUTION_CONTROLLER)))

    @override
    def runcmd(self, cmd: str) -> str:
        return self.dbg._execute_lldb_command(cmd)


class LLDBCommand(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, handler_name: str, command_name: str):
        self.handler_name = handler_name
        self.command_name = command_name


class LLDBPythonState(enum.Enum):
    """
    State of LLDB Python execution.

    Unlike in pwndbg-gdb, in pwndbg-lldb the responsibility of driving execution
    of Python code forward is shared between Pwndbg and LLDB. Knowing which one
    is in charge is crucial to the correct functioning of the Pwndbg REPL.

    This class defines the different kinds of states we can be in.
    """

    PWNDBG = 1
    "Pwndbg is driving execution of Python code"

    LLDB_COMMAND_HANDLER = 0
    "Python code is executing from inside an LLDB command handler"

    LLDB_STOP_HANDLER = 2
    "Python code is executing from an LLDB breakpoint/watchpoint hook handler"


def _default_lldb_python_state_callback(_state: LLDBPythonState) -> None:
    """
    Before being set by the Pwndbg REPL, LLDB instances need a sensible default
    value for lldb_python_state_callback. This is it.
    """
    raise RuntimeError("Pwndbg REPL failed to set lldb_python_state_callback")


class LLDB(pwndbg.dbg_mod.Debugger):
    exec_states: list[lldb.SBExecutionState]

    # We keep track of all installed event handlers here. The REPL will trigger
    # them by means of the `_trigger_event()` method.
    event_handlers: dict[
        pwndbg.dbg_mod.EventType, dict[EventHandlerPriority, list[Callable[..., None]]]
    ]

    # Event types may be suspended. We keep track of that here.
    suspended_events: dict[pwndbg.dbg_mod.EventType, bool]

    # The prompt hook fired right before the prompt is displayed.
    prompt_hook: Callable[[], None]

    # Whether the currently active process has direct accesss to the GDB remote
    # protocol. The REPL controls this field.
    _current_process_is_gdb_remote: bool

    # Queued up process control coroutines from the last Pwndbg command. We
    # should run these in order as soon as the command is over, but before we
    # return control to the user.
    controllers: list[tuple[LLDBProcess, Coroutine[Any, Any, None]]]

    # Relay used for exceptions originating from commands called through LLDB.
    _exception_relay: BaseException | None

    lldb_python_state_callback: Callable[[LLDBPythonState], None]
    "Callback to the REPL, used to notify it of LLDB driving Python code"

    # temporarily suspend context output
    should_suspend_ctx: bool

    @override
    def setup(self, *args, **kwargs):
        import pwnlib.update

        pwnlib.update.disabled = True

        self.exec_states = []
        self.event_handlers = {}
        self.controllers = []
        self._current_process_is_gdb_remote = False
        self._exception_relay = None
        self.lldb_python_state_callback = _default_lldb_python_state_callback
        self.should_suspend_ctx = False
        self._history_list = []
        self._history_index = 0

        import pwndbg

        self.suspended_events = dict.fromkeys(pwndbg.dbg_mod.EventType, False)

        debugger: lldb.SBDebugger = args[0]
        assert debugger.__class__ is lldb.SBDebugger, (
            "lldbinit.py should call setup() with an lldb.SBDebugger object"
        )

        module = args[1]
        assert module.__class__ is str, "lldbinit.py should call setup() with __name__"

        self.module = module
        self.debugger = debugger

        self.debug = kwargs.get("debug", False)

        from pwndbg.aglib import load_aglib

        load_aglib()

        # Load all of our commands.
        import pwndbg.commands
        import pwndbg.commands.comments

        pwndbg.commands.load_commands()

        pwndbg.commands.comments.init()

        # Register event hooks.
        # (We can't do them in this file because pwndbg.dbg isn't initialized yet.)
        from pwndbg.dbg_mod.lldb import hooks as hooks

    def relay_exceptions(self) -> None:
        """
        Relay an exception raised during an LLDB command handler.
        """
        e = self._exception_relay
        self._exception_relay = None
        if e is not None:
            if isinstance(e, CancelledError):
                # Cancellations are meaningful to the CLI, raise them unchanged.
                raise e

            raise pwndbg.dbg_mod.Error(e)

    def _execute_lldb_command(self, command: str) -> str:
        result = lldb.SBCommandReturnObject()
        self.debugger.GetCommandInterpreter().HandleCommand(
            command,
            result,
            False,
        )
        if not result.Succeeded():
            if result.GetErrorSize() > 0:
                raise pwndbg.dbg_mod.Error(result.GetError())
            raise pwndbg.dbg_mod.Error("lldb command failed without error")
        return result.GetOutput()

    @override
    def add_command(
        self,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
        subcommand_names: list[str] | None = None,
    ) -> pwndbg.dbg_mod.CommandHandle:
        debugger = self

        # LLDB commands are classes. So we create a new class for every command
        # that we want to register, which calls the handler we've been given.
        class CommandHandler:
            def __init__(self, debugger, _):
                pass

            def __call__(self, _, command, exe_context, result):
                try:
                    debugger.exec_states.append(exe_context)
                    debugger.lldb_python_state_callback(LLDBPythonState.LLDB_COMMAND_HANDLER)
                    handler(debugger, command, True)
                except BaseException as e:
                    debugger._exception_relay = e
                finally:
                    debugger.lldb_python_state_callback(LLDBPythonState.PWNDBG)
                    assert debugger.exec_states.pop() == exe_context, (
                        "Execution state mismatch on command handler"
                    )

            def get_repeat_command(self, command: str) -> str:
                return f"{name} {command}" if command else name

        # LLDB is very particular with the object paths it will accept. It is at
        # its happiest when its pulling objects straight off the module that was
        # first imported with `command script import`, so, we install the class
        # we've just created as a global value in its dictionary.
        handler_name = f"__LLDB_COMMAND_{name}"

        if self.debug:
            print(f"[-] LLDB: Adding command {name}, under the path {self.module}.{handler_name}")

        sys.modules[self.module].__dict__[handler_name] = CommandHandler

        # Install the command under the name we've just picked.
        self.debugger.HandleCommand(
            f"command script add -c {self.module}.{handler_name} -s synchronous {name}"
        )

        return LLDBCommand(handler_name, name)

    @override
    def history(self, last: int = 10) -> list[tuple[int, str]]:
        return self._history_list[-last:]

    @override
    def commands(self) -> list[str]:
        # Figure out a way to retrieve the command list later.
        return []

    @override
    def lex_args(self, command_line: str) -> list[str]:
        return shlex.split(command_line)

    def _any_inferior(self) -> LLDBProcess:
        """
        Pick the first inferior in the debugger, if any is present.

        Raises:
            pwndbg.dbg_mod.NoInferior: If we couldn't find an inferior.
        """
        target_count = self.debugger.GetNumTargets()
        if target_count == 0:
            # No targets are available.
            raise pwndbg.dbg_mod.NoInferior
        if target_count > 1:
            # We don't support multiple targets.
            raise RuntimeError("Multiple LLDB targets are not supported")

        target = self.debugger.GetTargetAtIndex(0)
        assert target.IsValid(), "Target must be valid at this point"

        process = target.GetProcess()
        if not process.IsValid():
            # No process we can use.
            raise pwndbg.dbg_mod.NoInferior

        return LLDBProcess(self, process, target, self._current_process_is_gdb_remote)

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process:
        if len(self.exec_states) == 0:
            # The Debugger-agnostic API treats existence of an inferior the same
            # as it being selected, as multiple inferiors are not supported, so
            # we lie a little here, and treat the only inferior as always
            # selected.
            return self._any_inferior()

        p = self.exec_states[-1].process
        t = self.exec_states[-1].target

        if p.IsValid() and t.IsValid():
            return LLDBProcess(self, p, t, self._current_process_is_gdb_remote)

        raise pwndbg.dbg_mod.NoInferior

    def _any_thread(self) -> LLDBThread | None:
        """
        Pick the first thread we can get our hands on, preferring the selected
        thread, if any is selected.
        """
        try:
            inferior: LLDBProcess = cast(LLDBProcess, self.selected_inferior())
        except pwndbg.dbg_mod.NoInferior:
            return None

        selected = inferior.process.GetSelectedThread()
        if selected is not None and selected.IsValid():
            return LLDBThread(selected, inferior)

        if inferior.process.GetNumThreads() <= 0:
            return None

        return LLDBThread(inferior.process.GetThreadAtIndex(0), inferior)

    @override
    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        if len(self.exec_states) == 0:
            return self._any_thread()

        t = self.exec_states[-1].thread
        if t.IsValid():
            inf_q = self.selected_inferior()
            assert isinstance(inf_q, LLDBProcess), (
                "LLDB.selected_inferior() must be an instance of LLDBProcess"
            )
            inf: LLDBProcess = inf_q

            return LLDBThread(t, inf)

        return None

    def _any_bottommost_frame(self) -> LLDBFrame | None:
        """
        Pick the first frame we can get our hands on, preferring the selected
        frame, if any is selected, and always picking the lowest frame on the
        stack otherwise.
        """
        thread: LLDBThread | None = self.selected_thread()
        if thread is None:
            return None

        selected = thread.inner.GetSelectedFrame()
        if selected is not None and selected.IsValid():
            return LLDBFrame(selected, thread.proc)

        if thread.inner.GetNumFrames() <= 0:
            return None

        return LLDBFrame(thread.inner.GetFrameAtIndex(0), thread.proc)

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        if len(self.exec_states) == 0:
            return self._any_bottommost_frame()

        f = self.exec_states[-1].frame
        if f.IsValid():
            inf_q = self.selected_inferior()
            assert isinstance(inf_q, LLDBProcess), (
                "LLDB.selected_inferior() must be an instance of LLDBProcess"
            )
            inf: LLDBProcess = inf_q

            return LLDBFrame(f, inf)

        return None

    @override
    def has_event_type(self, ty: pwndbg.dbg_mod.EventType) -> bool:
        # We don't support memory read and write events.
        return ty not in {
            pwndbg.dbg_mod.EventType.MEMORY_CHANGED,
            pwndbg.dbg_mod.EventType.REGISTER_CHANGED,
        }

    @override
    def event_handler(
        self,
        event_type: pwndbg.dbg_mod.EventType,
        priority: EventHandlerPriority = EventHandlerPriority.STANDARD,
    ) -> Callable[[Callable[..., None]], Callable[..., None]]:
        # Note that event_handler is actually a decorator factory and
        # not a decorator itself - it returns a decorator which is then
        # immediately applied to the function.
        def decorator(fn: Callable[..., None]) -> Callable[..., None]:
            if pwndbg.config.dev_debug_events:
                print("Connecting", fn.__name__, event_type.name)

            if event_type not in self.event_handlers:
                self.event_handlers[event_type] = {priority: []}
            elif priority not in self.event_handlers[event_type]:
                self.event_handlers[event_type][priority] = []

            # Wrap the function for dev instrumentation
            @functools.wraps(fn)
            def _dev_wrapper(*a, **kw) -> None:
                if pwndbg.config.dev_debug_events:
                    sys.stdout.write(
                        f"{event_type.name} ({priority.name}) {fn.__module__}.{fn.__qualname__}\n"
                    )

                return fn(*a, **kw)

            self.event_handlers[event_type][priority].append(_dev_wrapper)
            return _dev_wrapper

        return decorator

    @override
    @contextmanager
    def ctx_suspend_once(self):
        self.should_suspend_ctx = True

    @override
    def suspend_events(self, ty: pwndbg.dbg_mod.EventType) -> None:
        self.suspended_events[ty] = True

    @override
    def resume_events(self, ty: pwndbg.dbg_mod.EventType) -> None:
        self.suspended_events[ty] = False

    def _fire_prompt_hook(self) -> None:
        """
        The REPL calls this function in order to signal that the prompt hooks
        should be executed.
        """
        if self.prompt_hook:
            self.prompt_hook()

    def _trigger_event(self, ty: pwndbg.dbg_mod.EventType) -> None:
        """
        The REPL calls this function in order to signal that a given event type
        has occurred.
        """
        if ty not in self.event_handlers:
            # No one cares about this event type.
            return
        if self.suspended_events[ty] or self.suspended_events[pwndbg.dbg_mod.EventType.SUSPEND_ALL]:
            # This event has been suspended.
            return

        try:
            # Run the handlers in order of their priority.
            # We should optimize this by using a Dict[EventType, List[Tuple[EventHandlerPriority, Callable[..., None]]]]
            # type for self.event_handlers, and sort it only once after everything is registered.
            for prio in EventHandlerPriority:
                handlers = self.event_handlers[ty].get(prio, [])
                for handler in handlers:
                    handler()
        except Exception as e:
            from pwndbg.exception import handle as pwndbg_exception

            pwndbg_exception()
            raise e

    @override
    def set_sysroot(self, sysroot: str) -> bool:
        return self.debugger.SetCurrentPlatformSDKRoot(sysroot)

    @override
    def supports_breakpoint_creation_during_stop_handler(self) -> bool:
        return True

    @override
    def breakpoint_locations(self) -> list[pwndbg.dbg_mod.BreakpointLocation]:
        try:
            inferior: LLDBProcess = cast(LLDBProcess, self.selected_inferior())
        except pwndbg.dbg_mod.NoInferior:
            return []

        bps: list[lldb.SBBreakpoint] = inferior.target.breakpoints
        locations: list[pwndbg.dbg_mod.BreakpointLocation] = []
        for bp in bps:
            if bp.IsValid() and bp.IsEnabled():
                for location in bp.locations:
                    locations.append(location.GetAddress().GetLoadAddress(inferior.target))
        return locations

    @override
    def name(self) -> pwndbg.dbg_mod.DebuggerType:
        return pwndbg.dbg_mod.DebuggerType.LLDB

    @override
    def x86_disassembly_flavor(self) -> Literal["att", "intel"]:
        # Example:
        # (lldb) settings show target.x86-disassembly-flavor
        # target.x86-disassembly-flavor (enum) = default
        #
        result = self._execute_lldb_command("settings show target.x86-disassembly-flavor")
        flavor = result.split("=")[1].strip()
        if flavor == "default":
            flavor = "intel"

        if flavor not in {"att", "intel"}:
            raise pwndbg.dbg_mod.Error(f"unrecognized disassembly flavor '{flavor}'")

        literal: Literal["att", "intel"] = flavor
        return literal

    @override
    def string_limit(self) -> int:
        return 200

    @override
    def get_cmd_window_size(self) -> tuple[int, int]:
        return None, None

    @override
    @property
    def pre_ctx_lines(self) -> int:
        # We control the REPL, and we don't print any extra lines
        return 0

    @override
    def is_gdblib_available(self):
        return False

    @override
    def addrsz(self, address: Any) -> str:
        return f"{address:#16x}"

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        pass

    @override
    def set_convenience_var(self, name: str, value: str, type: str | None) -> None:
        """
        Set a convenience variable which will be accessible with $name in the
        debugger.

        Read the docstring in pwndbg.dbg.set_convenience_var()!!

        Surround this function with try/except.
        """
        # The `type` parameter is unused, we coerce void* in LLDB.
        try:
            # https://stackoverflow.com/questions/11192511/does-lldb-have-convenience-variables-var
            self._execute_lldb_command(f"expr void* ${name} = ((void*)({value}))")
        except pwndbg.dbg_mod.Error as e:
            if "redefinition" in str(e).lower():
                # The variable is already defined with a set type, we can try to set the value
                # anyway and hope for the best. The brackets are important.
                self._execute_lldb_command(f"expr ${name} = ((void*){value})")
            else:
                raise e
