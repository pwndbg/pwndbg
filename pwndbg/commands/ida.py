import gdb
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.ida
import pwndbg.regs

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.events.stop
def j(*args):
    pc = int(gdb.selected_frame().pc())
    pwndbg.ida.Jump(pc)


if pwndbg.ida.available():
    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def up():
        f = gdb.selected_frame()
        o = f.older()

        if o:
            o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()

    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def down():
        f = gdb.selected_frame()
        o = f.newer()

        if o:
            o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()


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
