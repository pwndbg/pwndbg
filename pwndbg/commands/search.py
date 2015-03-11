import gdb
import pwndbg.commands
import pwndbg.memory
import pwndbg.types

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def search(searchfor):
    value = None
    size  = None

    if isinstance(searchfor, gdb.Value):
        try:
            searchfor = pwndbg.memory.read(searchfor.address, searchfor.sizeof)
        except:
            searchfor = 0
    print(searchfor)
