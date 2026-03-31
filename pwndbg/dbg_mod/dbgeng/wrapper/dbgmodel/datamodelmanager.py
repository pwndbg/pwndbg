from ctypes import *
from typing import TYPE_CHECKING

from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.modelobject import ModelObject

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes.automation import VARIANT
import comtypes.gen.DbgMod as DbgModel


class DataModelManager:
    def __init__(self, inner: "_Pointer[DbgModel.IDataModelManager]"):
        self.inner = inner

    def GetRootNamespace(self) -> ModelObject:
        root = POINTER(DbgModel.IModelObject)()
        self.inner.GetRootNamespace(byref(root))
        return ModelObject(root)

    def CreateIntrinsicObject(self, kind: DbgModel.ModelObjectKind, data: VARIANT) -> ModelObject:
        obj = POINTER(DbgModel.IModelObject)()
        self.inner.CreateIntrinsicObject(kind, byref(data), byref(obj))
        return ModelObject(obj)
