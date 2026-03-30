import os
tlb = os.path.join(os.path.dirname(__file__), 'DbgModel.tlb')

import comtypes.client
comtypes.client.GetModule(tlb)
import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughost import DebugHost
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext, USE_CURRENT_HOST_CONTEXT
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostevaluator import DebugHostEvaluator
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.datamodelmanager import DataModelManager
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostmemory import DebugHostMemory
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostmodule import DebugHostModule
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbol import DebugHostSymbol
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbols import DebugHostSymbols
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughosttype import DebugHostType
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.hostdatamodelaccess import HostDataModelAccess
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.modelobject import ModelObject
