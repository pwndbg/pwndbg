from __future__ import annotations

import ctypes
import io
import sys

from pwndbg.dbg_mod.dbgeng.wrapper.dbgeng import DebugCreate
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel import DbgModel
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel import HostDataModelAccess


def main():
    # DbgEng objects
    dbgclient = DebugCreate()
    dbgcontrol = dbgclient.DebugControl()
    dbgsysobjects = dbgclient.DebugSystemObjects()
    dbgregisters = dbgclient.DebugRegisters()
    dbgadvanced = dbgclient.DebugAdvanced()
    dbgsymbols = dbgclient.DebugSymbols()
    dbgdataspaces = dbgclient.DebugDataSpaces()

    # DbgModel objects
    hostdatamodelaccess = HostDataModelAccess(dbgclient.QueryInterface(interface=DbgModel.IHostDataModelAccess))
    datamodelmanager, debughost = hostdatamodelaccess.GetDataModel()
    debughostsymbols = debughost.DebugHostSymbols()
    debughostevaluator = debughost.DebugHostEvaluator()
    debughostmemory = debughost.DebugHostMemory()

    # initialize pwndbg
    import pwndbg
    import pwndbg.dbg_mod.dbgeng
    pwndbg.dbg_mod.dbgeng.dbgclient = dbgclient
    pwndbg.dbg_mod.dbgeng.dbgcontrol = dbgcontrol
    pwndbg.dbg_mod.dbgeng.dbgsysobjects = dbgsysobjects
    pwndbg.dbg_mod.dbgeng.dbgregisters = dbgregisters
    pwndbg.dbg_mod.dbgeng.dbgadvanced = dbgadvanced
    pwndbg.dbg_mod.dbgeng.dbgsymbols = dbgsymbols
    pwndbg.dbg_mod.dbgeng.dbgdataspaces = dbgdataspaces

    pwndbg.dbg_mod.dbgeng.hostdatamodelaccess = hostdatamodelaccess
    pwndbg.dbg_mod.dbgeng.datamodelmanager = datamodelmanager
    pwndbg.dbg_mod.dbgeng.debughost = debughost
    pwndbg.dbg_mod.dbgeng.debughostsymbols = debughostsymbols
    pwndbg.dbg_mod.dbgeng.debughostevaluator = debughostevaluator
    pwndbg.dbg_mod.dbgeng.debughostmemory = debughostmemory

    # setup the debugger
    pwndbg.dbg = pwndbg.dbg_mod.dbgeng.DbgEng()
    command_dispatcher = pwndbg.dbg_mod.dbgeng.CommandDispatcher(pwndbg.dbg)
    pwndbg.dbg.setup(command_dispatcher)
    globals()["dispatch"] = command_dispatcher.dispatch

if __name__ == "__main__":
    main()
