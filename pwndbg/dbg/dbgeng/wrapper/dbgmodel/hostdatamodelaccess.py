from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.datamodelmanager import DataModelManager
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughost import DebugHost


class HostDataModelAccess:
    def __init__(self, inner: "_Pointer[DbgModel.IHostDataModelAccess]"):
        self.inner = inner
    
    def GetDataModel(self) -> tuple[DataModelManager, DebugHost]:
        dataModelManager = POINTER(DbgModel.IDataModelManager)()
        debugHost = POINTER(DbgModel.IDebugHost)()

        self.inner.GetDataModel(byref(dataModelManager), byref(debugHost))
        return DataModelManager(dataModelManager), DebugHost(debugHost)
