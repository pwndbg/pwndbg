import gdb
import pwndbg.commands
import pwndbg.ida
import pwndbg.regs


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def j(*args):
    pc = pwndbg.regs.pc
    pwndbg.ida.Jump(pc)

class ida(gdb.Function):
    """
    Return a value from IDA that can be used in
    native GDB expressions.
    """
    def __init__(self):
        super(ida, self).__init__('ida')
    def invoke(self, name):
        return pwndbg.ida.LocByName(name.string())

ida()
