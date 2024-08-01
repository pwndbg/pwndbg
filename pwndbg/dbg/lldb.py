from __future__ import annotations

import sys
from typing import Any
from typing import Callable
from typing import List
from typing import Tuple

import lldb
from typing_extensions import override

import pwndbg


class LLDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: lldb.SBFrame):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        value = self.inner.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value)


def map_type_code(type: lldb.SBType) -> pwndbg.dbg_mod.TypeCode:
    """
    Determines the type code of a given LLDB SBType.
    """
    c = type.GetTypeCode()

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
    def __init__(self, inner: lldb.SBType):
        self.inner = inner

    @property
    @override
    def alignof(self) -> int:
        return self.inner.GetByteAlign()

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        return map_type_code(self.inner)

    @override
    def fields(self) -> List[pwndbg.dbg_mod.TypeField] | None:
        fields = self.inner.get_fields_array()
        return (
            [
                pwndbg.dbg_mod.TypeField(
                    field.bit_offset,
                    field.name,
                    LLDBType(field.type),
                    self,
                    0,  # TODO: Handle fields for enum types differently.
                    False,
                    False,  # TODO: Handle base class members differently.
                    field.bitfield_bit_size if field.is_bitfield else field.type.GetByteSize(),
                )
                for field in fields
            ]
            if len(fields) > 0
            else None
        )

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
            t = t.GetTypedefedType

        return LLDBType(t)

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        t = self.inner.GetPointeeType()
        if not t.IsValid():
            raise pwndbg.dbg_mod.Error("tried to get target type of non-pointer type")

        return LLDBType(t)


class LLDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: lldb.SBValue):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        addr = self.inner.AddressOf()
        return LLDBValue(addr) if addr.IsValid() else None

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

        if not deref.IsValid():
            raise pwndbg.dbg_mod.Error("could not dereference value")

        return LLDBValue(deref)

    @override
    def string(self) -> str:
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
    def fetch_lazy(self) -> None:
        # Not needed under LLDB.
        pass

    @override
    def __int__(self) -> int:
        return self.inner.signed

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        assert isinstance(type, LLDBType)
        t: LLDBType = type

        return LLDBValue(self.inner.Cast(t.inner))


class LLDBProcess(pwndbg.dbg_mod.Process):
    def __init__(self, process: lldb.SBProcess, target: lldb.SBTarget):
        self.process = process
        self.target = target

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        value = self.target.EvaluateExpression(expression)
        opt_out = _is_optimized_out(value)

        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value)


class LLDBCommand(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, handler_name: str, command_name: str):
        self.handler_name = handler_name
        self.command_name = command_name


class LLDB(pwndbg.dbg_mod.Debugger):
    exec_states: List[lldb.SBExecutionState]

    @override
    def setup(self, *args):
        self.exec_states = []

        debugger = args[0]
        assert (
            debugger.__class__ is lldb.SBDebugger
        ), "lldbinit.py should call setup() with an lldb.SBDebugger object"

        module = args[1]
        assert module.__class__ is str, "lldbinit.py should call setup() with __name__"

        self.module = module
        self.debugger = debugger

        import pwndbg.commands

        pwndbg.commands.load_commands()

        import argparse

        parser = argparse.ArgumentParser(description="Prints a test message.")

        @pwndbg.commands.ArgparsedCommand(parser)
        def test2():
            print("Test 2!")

    @override
    def add_command(
        self, command_name: str, handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]
    ) -> pwndbg.dbg_mod.CommandHandle:
        debugger = self

        # LLDB commands are classes. So we create a new class for every command
        # that we want to register, which calls the handler we've been given.
        class CommandHandler:
            def __init__(self, debugger, _):
                pass

            def __call__(self, _, command, exe_context, result):
                debugger.exec_states.append(exe_context)
                handler(debugger, command, True)
                assert (
                    debugger.exec_states.pop() == exe_context
                ), "Execution state mismatch on command handler"

        # LLDB is very particular with the object paths it will accept. It is at
        # its happiest when its pulling objects straight off the module that was
        # first imported with `command script import`, so, we install the class
        # we've just created as a global value in its dictionary.
        name = f"__LLDB_COMMAND_{command_name}"
        print(f"adding command {command_name}, under the path {self.module}.{name}")

        sys.modules[self.module].__dict__[name] = CommandHandler

        # Install the command under the name we've just picked.
        self.debugger.HandleCommand(
            f"command script add -c {self.module}.{name} -s synchronous {command_name}"
        )

        return LLDBCommand(name, command_name)

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # Figure out a way to retrieve history later.
        # Just need to parse the result of `self.inner.HandleCommand("history")`
        return []

    @override
    def commands(self) -> List[str]:
        # Figure out a way to retrieve the command list later.
        return []

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return command_line.split()

    def first_inferior(self) -> LLDBProcess | None:
        """
        Pick the first inferior in the debugger, if any is present.
        """
        target_count = self.debugger.GetNumTargets()
        if target_count == 0:
            # No targets are available.
            return None
        if target_count > 1:
            # We don't support multiple targets.
            raise RuntimeError("Multiple LLDB targets are not supported")

        target = self.debugger.GetTargetAtIndex(0)
        assert target.IsValid(), "Target must be valid at this point"

        process = target.GetProcess()
        if not process.IsValid():
            # No process we can use.
            return None

        return LLDBProcess(process, target)

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        if len(self.exec_states) == 0:
            # The Debugger-agnostic API treats existence of an inferior the same
            # as it being selected, as multiple inferiors are not supported, so
            # we lie a little here, and treat the only inferior as always
            # selected.
            return self.first_inferior()

        p = self.exec_states[-1].process
        t = self.exec_states[-1].target

        if p.IsValid() and t.IsValid():
            return LLDBProcess(p, t)

        return None

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        if len(self.exec_states) == 0:
            return None

        f = self.exec_states[-1].frame
        if f.IsValid():
            return LLDBFrame(f)

        return None

    @override
    def get_cmd_window_size(self) -> Tuple[int, int]:
        import pwndbg.ui

        return pwndbg.ui.get_window_size()

    def is_gdblib_available(self):
        return False

    @override
    def addrsz(self, address: Any) -> str:
        return "%#16x" % address

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        pass
