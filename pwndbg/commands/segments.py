import gdb
import pwndbg.regs

class segment(gdb.Function):
    def __init__(self, name):
        super(segment, self).__init__(name)
        self.name = name
    def invoke(self, arg):
        result = getattr(pwndbg.regs, self.name)
        return result + arg

segment('fsbase')
segment('gsbase')