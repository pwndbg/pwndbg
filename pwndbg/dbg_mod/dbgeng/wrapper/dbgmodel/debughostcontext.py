from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel


class DebugHostContext:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostContext]"):
        self.inner = inner

    def IsEqualTo(self, context: "DebugHostContext") -> bool:
        is_equal = c_int()
        self.inner.IsEqualTo(context.inner, byref(is_equal))
        return bool(is_equal.value)


USE_CURRENT_HOST_CONTEXT = DebugHostContext(cast(-1, POINTER(DbgModel.IDebugHostContext)))
