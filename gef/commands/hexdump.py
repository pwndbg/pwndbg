import gef.regs
import gef.commands
import gef.memory
import gef.hexdump

@gef.commands.ParsedCommand
@gef.commands.OnlyWhenRunning
def hexdump(address=None, count=64):
    """Hexdumps some data"""
    if address is None:
    	address = gef.regs.sp

    int(address)

    data = gef.memory.read(address, count)

    for line in gef.hexdump.hexdump(data, address=address):
        print(line)

