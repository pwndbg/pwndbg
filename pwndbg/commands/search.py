import gdb
import struct
import pwndbg.commands
import pwndbg.search
import pwndbg.enhance
import pwndbg.color

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def search(value):
    for address in pwndbg.search.search(value):
        print(pwndbg.color.get(address), pwndbg.enhance.enhance(address))