from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgEng as DbgEng


class DebugAdvanced:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugAdvanced2]"):
        self.inner = inner

    def Request(self, request: int, in_buffer: c_char_p, in_buffer_size: int, out_buffer: c_char_p, out_buffer_size: int) -> int:
        out_size = c_ulong()
        self.inner.Request(request, in_buffer, in_buffer_size, out_buffer, out_buffer_size, byref(out_size))
        return out_size.value
