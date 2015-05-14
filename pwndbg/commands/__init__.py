import functools
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

__all__ = [
'asm',
'auxv',
'context',
'dt',
'hexdump',
'ida',
'nearpc',
'packing',
'reload',
'rop',
'search',
'shell',
'start',
'telescope',
'vmmap',
'windbg',
]

debug = True

class Command(gdb.Command):
    count    = 0
    commands = []

    def __init__(self, function):
        super(Command, self).__init__(function.__name__, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)
        self.function = function

        Command.commands.append(self)
        functools.update_wrapper(self, function)

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

OnlyWhenRunning = pwndbg.proc.OnlyWhenRunning

@Command
def pwndbg():
    """Prints out a list of all pwndbg commands."""

    maxlen = max([len(C.function.__name__) for C in Command.commands])
    funcs = sorted(Command.commands, key=lambda x: x.function.__name__)

    for func in funcs:
        docstr = ''
        if func.__doc__:
            docstr = func.__doc__.strip().split('\n')[0]
        print(func.__name__.ljust(maxlen), docstr)
