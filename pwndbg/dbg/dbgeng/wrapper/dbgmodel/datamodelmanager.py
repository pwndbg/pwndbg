from ctypes import *
from typing import TYPE_CHECKING

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.modelobject import ModelObject

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult


class DataModelManager:
    def __init__(self, inner: "_Pointer[DbgModel.IDataModelManager]"):
        self.inner = inner

    def GetRootNamespace(self) -> ModelObject:
        root = POINTER(DbgModel.IModelObject)()
        self.inner.GetRootNamespace(byref(root))
        return ModelObject(root)
