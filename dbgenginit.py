import sys
import io
import ctypes
from comtypes.gen.DbgEng import DEBUG_OUTPUT_NORMAL, IDebugControl, IDebugSystemObjects, IDebugAdvanced2, IDebugSymbols

import pybag.dbgeng.core as core
from pybag.dbgeng.idebugclient import DebugClient


def main():
    from pwndbg.dbg.dbgeng.wrapper.systemobjects import DebugSystemObjects
    from pwndbg.dbg.dbgeng.wrapper.control import DebugControl
    from pwndbg.dbg.dbgeng.wrapper.registers import DebugRegisters
    from pwndbg.dbg.dbgeng.wrapper.advanced import DebugAdvanced
    from pwndbg.dbg.dbgeng.wrapper.symbols import DebugSymbols
    # from pwndbg.dbg.dbgeng.wrapper.client import DebugClient

    # core.DBGENG_DLL = "D:\\projects\\dbgeng\\dbgeng.dll"
    # dbgeng objects
    dbgclient = DebugClient()
    # dbgcontrol = dbgclient.IDebugControl()
    # dbgsysobjects = dbgclient.IDebugSystemObjects()
    dbgcontrol = DebugControl(dbgclient._cli.QueryInterface(interface=IDebugControl))
    dbgsysobjects = DebugSystemObjects(dbgclient._cli.QueryInterface(interface=IDebugSystemObjects))
    dbgregisters = dbgclient.IDebugRegisters()
    dbgadvanced = DebugAdvanced(dbgclient._cli.QueryInterface(interface=IDebugAdvanced2))
    dbgsymbols = DebugSymbols(dbgclient._cli.QueryInterface(interface=IDebugSymbols))

    # Initialize IO
    # sys.stdout = io.IOBase()

    # def write(msg):
    #     dbgcontrol._ctrl._IDebugControl7__com_Output.__func__.argtypes = (
    #         ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p)
    #     dbgcontrol._ctrl._IDebugControl7__com_Output(DEBUG_OUTPUT_NORMAL, "%s", msg)

    # sys.stdout.write = write
    # sys.stderr = sys.stdout

    # initialize pwndbg
    import pwndbg
    import pwndbg.dbg.dbgeng
    pwndbg.dbg_mod.dbgeng.dbgclient = dbgclient
    pwndbg.dbg_mod.dbgeng.dbgcontrol = dbgcontrol
    pwndbg.dbg_mod.dbgeng.dbgsysobjects = dbgsysobjects
    pwndbg.dbg_mod.dbgeng.dbgregisters = dbgregisters
    pwndbg.dbg_mod.dbgeng.dbgadvanced = dbgadvanced
    pwndbg.dbg_mod.dbgeng.dbgsymbols = dbgsymbols

    # setup the debugger
    pwndbg.dbg = pwndbg.dbg_mod.dbgeng.DbgEng()
    command_dispatcher = pwndbg.dbg_mod.dbgeng.CommandDispatcher(pwndbg.dbg)
    pwndbg.dbg.setup(command_dispatcher)
    globals()["dispatch"] = command_dispatcher.dispatch

    # temporarily enable verbosed exceptions
    pwndbg.config.exception_verbose.value = True

if __name__ == "__main__":
    main()
