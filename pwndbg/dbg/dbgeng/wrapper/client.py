from ctypes import *

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult


class DebugClient:
    def __init__(self, inner: DbgEng.IDebugClient7):
        self.inner = inner
    
    def SetEventCallbacks(self, callbacks: DbgEng.IDebugEventCallbacks) -> None:
        self.inner.SetEventCallbacks(byref(callbacks))
