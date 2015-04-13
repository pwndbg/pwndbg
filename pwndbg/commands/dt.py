import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.dt
import pwndbg.vmmap


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def dt(typename, address=None):
    if address is not None:
        address = pwndbg.commands.fix(address)
    print(pwndbg.dt.dt(typename, addr=address))
