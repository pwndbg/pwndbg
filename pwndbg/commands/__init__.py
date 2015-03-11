import traceback
import gdb

import pwndbg.regs
import pwndbg.memory
import pwndbg.hexdump
import pwndbg.color
import pwndbg.chain
import pwndbg.enhance
import pwndbg.symbol
import pwndbg.ui
import pwndbg.proc

debug = True

class ParsedCommand(gdb.Command):
    def __init__(self, function):
        super(ParsedCommand, self).__init__(function.__name__, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)
        self.function = function

    def invoke(self, argument, from_tty):
        argv = gdb.string_to_argv(argument)

        for i,arg in enumerate(argv):
            try:
                argv[i] = gdb.parse_and_eval(arg)
                continue
            except Exception:
                pass

            try:
                arg = pwndbg.regs.fix(arg)
                argv[i] = gdb.parse_and_eval(arg)
            except Exception:
                pass

        try:
            self.function(*argv)
        except TypeError:
            if debug: print(traceback.format_exc())
            pass

    def __call__(self, *args, **kwargs):
        return self.function(*args, **kwargs)

def OnlyWhenRunning(func):
    def wrapper(*a, **kw):
        func.__doc__
        if not pwndbg.proc.alive:
            pass
        else:
            return func(*a, **kw)
    wrapper.__name__ = func.__name__
    wrapper.__module__ = func.__module__
    return wrapper