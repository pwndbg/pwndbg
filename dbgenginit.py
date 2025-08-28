import sys
import io
import ctypes
from comtypes.gen.DbgEng import DEBUG_OUTPUT_NORMAL

from pybag.dbgeng.idebugclient import DebugClient


def main():
    # dbgeng objects
    dbgclient = DebugClient()
    dbgcontrol = dbgclient.IDebugControl()
    dbgsysobjects = dbgclient.IDebugSystemObjects()
    dbgregisters = dbgclient.IDebugRegisters()

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

    # setup the debugger
    from pwndbg.dbg.dbgeng.dispatch import CommandDispatcher
    command_dispatcher = CommandDispatcher()
    pwndbg.dbg = pwndbg.dbg_mod.dbgeng.DbgEng()
    pwndbg.dbg.setup(command_dispatcher)
    globals()["dispatch"] = command_dispatcher.dispatch

if __name__ == "__main__":
    main()
