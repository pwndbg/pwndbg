import gdb
import pwndbg.vmmap
import pwndbg.commands
import pwndbg.color
import pwndbg.dt

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dt(typename, address=None):
    print(pwndbg.dt.dt(typename, addr=address))
