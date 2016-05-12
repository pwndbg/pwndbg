from __future__ import print_function
import gdb
import pwndbg.regs
import pwndbg.commands

class segment(gdb.Function):
    """Get the flat address of memory based off of the named segment register.
    """
    def __init__(self, name):
        super(segment, self).__init__(name)
        self.name = name
    def invoke(self, arg=0):
        result = getattr(pwndbg.regs, self.name)
        return result + arg

segment('fsbase')
segment('gsbase')

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.ParsedCommand
def fsbase():
    """
    Prints out the FS base address.  See also $fsbase.
    """
    print(hex(pwndbg.regs.fsbase))


@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.ParsedCommand
def gsbase():
    """
    Prints out the GS base address.  See also $gsbase.
    """
    print(hex(pwndbg.regs.gsbase))
