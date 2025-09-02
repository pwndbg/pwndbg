from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult


class KeyStore:
    def __init__(self, inner: "_Pointer[DbgModel.IKeyStore]"):
        self.inner = inner
