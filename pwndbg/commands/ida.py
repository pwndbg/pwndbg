import gdb
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.ida
import pwndbg.regs


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.events.stop
def j(*args):
    """
    Synchronize IDA's cursor with GDB
    """
    pc = int(gdb.selected_frame().pc())
    pwndbg.ida.Jump(pc)


if pwndbg.ida.available():
    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def up(n=1):
        """
        Select and print stack frame that called this one.
        An argument says how many frames up to go.
        """
        f = gdb.selected_frame()

        for i in range(n):
            o = f.older()
            if o:
                o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()

    @pwndbg.commands.Command
    @pwndbg.commands.OnlyWhenRunning
    def down(n=1):
        """
        Select and print stack frame called by this one.
        An argument says how many frames down to go.
        """
        f = gdb.selected_frame()

        for i in range(n):
            o = f.newer()
            if o:
                o.select()

        bt = pwndbg.commands.context.context_backtrace(with_banner=False)
        print('\n'.join(bt))

        j()


class ida(gdb.Function):
    """Evaluate ida.LocByName() on the supplied value.
    """
    def __init__(self):
        super(ida, self).__init__('ida')
    def invoke(self, name):
        return pwndbg.ida.LocByName(name.string())

ida()
