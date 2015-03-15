import pwndbg.ida
import pwndbg.commands
import pwndbg.regs

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def j(*args):
    pc = pwndbg.regs.pc
    pwndbg.ida.Jump(pc)

