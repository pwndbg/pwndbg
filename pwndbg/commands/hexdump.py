import pwndbg.regs
import pwndbg.commands
import pwndbg.memory
import pwndbg.hexdump

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def hexdump(address=None, count=64):
    """Hexdumps some data"""
    if address is None:
    	address = pwndbg.regs.sp

    int(address)

    data = pwndbg.memory.read(address, count)

    for line in pwndbg.hexdump.hexdump(data, address=address):
        print(line)

