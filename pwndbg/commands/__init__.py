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

class Command(gdb.Command):
    def __init__(self, function):
        super(Command, self).__init__(function.__name__, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)
        self.function = function

    def split_args(self, argument):
        return gdb.string_to_argv(argument)

    def invoke(self, argument, from_tty):
        argv = self.split_args(argument)

        try:
            return self.function(*argv)
        except TypeError:
            if debug:
                print(traceback.format_exc())
            raise

    def __call__(self, *args, **kwargs):
        return self.function(*args, **kwargs)


class ParsedCommand(Command):
    def split_args(self, argument):
        argv = super(ParsedCommand,self).split_args(argument)
        return list(filter(lambda x: x is not None, map(fix, argv)))

def fix(arg, sloppy=False):
    try:
        return gdb.parse_and_eval(arg)
    except Exception:
        pass

    try:
        arg = pwndbg.regs.fix(arg)
        return gdb.parse_and_eval(arg)
    except Exception:
        pass

    if sloppy:
        return arg

    return None

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