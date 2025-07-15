import sys
import io

from pybag.dbgeng.idebugclient import DebugClient


def main():
    # dbgeng objects
    dbgclient = DebugClient()
    dbgsysobjects = dbgclient.IDebugSystemObjects()
    dbgregisters = dbgclient.IDebugRegisters()

    # Initialize IO
    sys.stdout = io.IOBase()
    dbgcontrol = dbgclient.IDebugControl()
    sys.stdout.write = lambda msg: dbgcontrol.Output("%s", msg)
    sys.stderr = sys.stdout

    # initialize pwndbg
    import pwndbg
    import pwndbg.dbg.dbgeng
    pwndbg.dbg_mod.dbgeng.dbgclient = dbgclient
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
