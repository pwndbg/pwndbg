from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult

from pwndbg.dbg.dbgeng.wrapper.dbgeng.control import DebugControl
from pwndbg.dbg.dbgeng.wrapper.dbgeng.advanced import DebugAdvanced
from pwndbg.dbg.dbgeng.wrapper.dbgeng.registers import DebugRegisters
from pwndbg.dbg.dbgeng.wrapper.dbgeng.symbols import DebugSymbols
from pwndbg.dbg.dbgeng.wrapper.dbgeng.systemobjects import DebugSystemObjects


class DebugClient:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugClient7]"):
        self.inner = inner

    def QueryInterface(self, interface) -> c_void_p:
        return self.inner.QueryInterface(interface)

    def DebugAdvanced(self) -> DebugAdvanced:
        return DebugAdvanced(self.inner.QueryInterface(DbgEng.IDebugAdvanced2))

    def DebugControl(self) -> DebugControl:
        return DebugControl(self.inner.QueryInterface(DbgEng.IDebugControl))

    def DebugRegisters(self) -> DebugRegisters:
        return DebugRegisters(self.inner.QueryInterface(DbgEng.IDebugRegisters))

    def DebugSymbols(self) -> DebugSymbols:
        return DebugSymbols(self.inner.QueryInterface(DbgEng.IDebugSymbols))

    def DebugSystemObjects(self) -> DebugSystemObjects:
        return DebugSystemObjects(self.inner.QueryInterface(DbgEng.IDebugSystemObjects))

    def SetEventCallbacks(self, callbacks: "_Pointer[DbgEng.IDebugEventCallbacks]") -> None:
        self.inner.SetEventCallbacks(callbacks)
