from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult


class DebugHostContext:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostContext]"):
        self.inner = inner


USE_CURRENT_HOST_CONTEXT = DebugHostContext(cast(-1, POINTER(DbgModel.IDebugHostContext)))
