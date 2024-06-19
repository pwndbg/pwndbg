from __future__ import annotations

from typing import Any
from typing import Tuple

import lldb
from typing_extensions import override

import pwndbg

class LLDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: lldb.SBFrame):
        self.inner = inner

    @override
    def evaluate_expression(self, expression):
        value = self.inner.EvaluateExpression(expression)
        opt_out = is_optimized_out(value)
    
        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value, opt_out)
        
def map_type_code(type: lldb.SBType) -> pwndbg.dbg_mod.TypeCode:
    """
    Determines the type code of a given LLDB SBType.
    """
    c = type.GetTypeCode()
    f = type.GetTypeFlags()

    assert c != lldb.eTypeClassInvalid, \
        "passed eTypeClassInvalid to map_type_code"

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

    if f & lldb.eTypeIsInteger != 0:
        return pwndbg.dbg_mod.TypeCode.INT
    
    raise RuntimeError("missing mapping for type code")

def is_optimized_out(value: lldb.SBValue) -> bool:
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

    def alignof(self):
        return self.inner.GetByteAlign()

    def code(self):
        return map_type_code(self.inner)

    def fields(self):
        fields = self.inner.get_fields_array()
        return [LLDBType(t) for t in fields] if len(fields) > 0 else None

    def array(self, count):
        return LLDBType(self.inner.GetArrayType(count))

    def pointer(self):
        return LLDBType(self.inner.GetPointerType())

    def strip_typedefs(self):
        t = self.inner
        while t.IsTypedefType():
            t = t.GetTypedefedType

        return LLDBType(t)
    
    def target(self):
        t = self.inner.GetPointeeType()
        if not t.IsValid():
            raise pwndbg.dbg_mod.Error("tried to get target type of non-pointer type")
    
        return LLDBType(t)

class LLDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: lldb.SBValue):
        self.inner = inner

    @override
    def address(self):
        addr = self.inner.AddressOf()
        return LLDBValue(addr) if addr.IsValid() else None

    @override
    def is_optimized_out(self):
        return is_optimised_out(self.inner)

    @override
    def type(self):
        assert not self.is_optimized_out(), \
            "tried to get type of optimized-out value"

        return LLDBType(self.type)

    @override
    def dereference(self):
        deref = self.inner.Dereference()

        if not deref.IsValid():
            raise pwndbg.dbg_api.Error(f"could not dereference value")

        return LLDBValue(deref)
    
    @override
    def string(self):
        addr = self.inner.unsigned
        error = lldb.SBError()

        # Read strings up to 4GB.
        last_str = None
        buf = 256
        for i in range(8, 33):
            s = self.inner.process.ReadCStringFromMemory(addr, buf, error)
            if error.Fail():
                raise pwndbg.dbg_api.Error(f"could not read value as string: {error.description}")
            if last_str is not None and len(s) == len(last_str):
                break
            last_str = s

            buf *= 2
        
        return last_str

    @override
    def fetch_lazy(self):
        # Not needed under LLDB.
        pass

    @override
    def __int__(self):
        return self.inner.signed

    @override
    def cast(self, type):
        return LLDBValue(self.inner.Cast(type.inner))

class LLDBProcess(pwndbg.dbg_mod.Process):
    def __init__(self, process: lldb.SBProcess, target: lldb.SBTarget):
        self.process = process
        self.target = target

    @override
    def threads(self):
        pass

    @override
    def evaluate_expression(self, expression):
        value = self.target.EvaluateExpression(expression)
        opt_out = is_optimized_out(value)
    
        if not value.error.Success() and not opt_out:
            raise pwndbg.dbg_mod.Error(value.error.description)

        return LLDBValue(value, opt_out)
        

class LLDBSession(pwndbg.dbg_mod.Session):
    @override
    def history(self):
        # Figure out a way to retrieve history later.
        return []

    @override
    def commands(self):
        # Figure out a way to retrieve the command list later.
        return []

    @override
    def lex_args(self, command_line):
        return command_line.split()

    @override
    def selected_inferior(self):
        p = lldb.process
        t = lldb.target

        if p.IsValid() and t.IsValid():
            return LLDBProcess(p, t)

    @override
    def selected_frame(self):
        f = lldb.frame
        if f.IsValid():
            return LLDBFrame(f)

class LLDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self, *args):
        debugger = args[0]
        assert (
            debugger.__class__ is lldb.SBDebugger
        ), "lldbinit.py should call setup() with an lldb.SBDebugger object"

        self.debugger = debugger

        import pwndbg.commands

    @override
    def inferior(self):
        target_count = self.debugger.GetNumTargets()
        if target_count == 0:
            # No targets are available.
            return None
        if target_count > 1:
            # We don't support multiple targets.
            raise RuntimeError("Multiple LLDB targets are not supported")

        target = self.debugger.GetTargetAtIndex(0)
        process = self.debugger.GetProcess()
        
        assert target.IsValid(), "Target must be valid at this point"
        if not process.IsValid():
            # No process we can use.
            return None

        return LLDBProcess(process, target)

    @override
    def session(self):
        return LLDBSession()

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
