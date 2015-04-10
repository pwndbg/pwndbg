import gdb
import pwndbg.commands
import pwndbg.chain
import pwndbg.auxv

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def auxv():
    for k,v in pwndbg.auxv.get().items():
        if v is not None:
            print(k.ljust(24), v if not isinstance(v, (long, int)) else pwndbg.chain.format(v))
