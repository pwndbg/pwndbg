import os
tlb = os.path.join(os.path.dirname(__file__), 'DbgModel.tlb')

import comtypes.client
comtypes.client.GetModule(tlb)
import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughost import DebugHost
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbols import DebugHostSymbols
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbol import DebugHostSymbol
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.hostdatamodelaccess import HostDataModelAccess
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.datamodelmanager import DataModelManager
