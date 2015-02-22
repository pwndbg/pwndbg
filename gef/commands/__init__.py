import traceback
import gdb

import gef.regs
import gef.memory
import gef.hexdump
import gef.color
import gef.chain
import gef.enhance
import gef.symbol
import gef.ui
import gef.proc

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
                arg = gef.regs.fix(arg)
                argv[i] = gdb.parse_and_eval(arg)
            except Exception:
                pass

        try:
            self.function(*argv)
        except TypeError:
            if debug: print(traceback.format_exc())
            pass

    def __call__(self, *args):
        self.function(*args)

def OnlyWhenRunning(func):
    def wrapper(*a):
        func.__doc__
        if not gef.proc.alive:
            pass
        else:
            func(*a)
    wrapper.__name__ = func.__name__
    wrapper.__module__ = func.__module__
    return wrapper


@ParsedCommand
@OnlyWhenRunning
def searchmem(searchfor):

    if isinstance(searchfor, gdb.Value):
        try:
            searchfor = gef.memory.read(searchfor.address, searchfor.sizeof)
        except:
            searchfor = 0
    print(searchfor)