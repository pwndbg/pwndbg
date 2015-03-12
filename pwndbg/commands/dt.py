import gdb
import pwndbg.vmmap
import pwndbg.commands
import pwndbg.color
import pwndbg.dt

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def dt(typename, address=None):
    if address is not None:
        address = pwndbg.commands.fix(address)
    print(pwndbg.dt.dt(typename, addr=address))
