import gdb
import gef.vmmap
import gef.commands
import gef.color
import gef.dt

@gef.commands.ParsedCommand
@gef.commands.OnlyWhenRunning
def dt(typename, address=None):
    print(gef.dt.dt(typename, addr=address))
