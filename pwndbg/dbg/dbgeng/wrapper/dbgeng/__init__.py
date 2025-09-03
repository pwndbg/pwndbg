from pybag.dbgeng.core import DebugCreate as DbgCreate

from pwndbg.dbg.dbgeng.wrapper.dbgeng.advanced import DebugAdvanced
from pwndbg.dbg.dbgeng.wrapper.dbgeng.client import DebugClient
from pwndbg.dbg.dbgeng.wrapper.dbgeng.control import DebugControl
from pwndbg.dbg.dbgeng.wrapper.dbgeng.dataspaces import DebugDataSpaces
from pwndbg.dbg.dbgeng.wrapper.dbgeng.registers import DebugRegisters
from pwndbg.dbg.dbgeng.wrapper.dbgeng.symbols import DebugSymbols
from pwndbg.dbg.dbgeng.wrapper.dbgeng.systemobjects import DebugSystemObjects

import comtypes.gen.DbgEng as DbgEng


def DebugCreate() -> DebugClient:
    client = DbgCreate()
    return DebugClient(client)
