import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.argv
import pwndbg.gdblib.typeinfo


@pwndbg.commands.ArgparsedCommand("Prints out the number of arguments.")
@pwndbg.commands.OnlyWhenRunning
def argc():
    print(pwndbg.gdblib.argv.argc)


parser = argparse.ArgumentParser()
parser.description = "Prints out the contents of argv."
parser.add_argument(
    "i", nargs="?", type=int, default=None, help="Index of the argument to print out."
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["args"])
@pwndbg.commands.OnlyWhenRunning
def argv(i=None):
    start = pwndbg.gdblib.argv.argv
    n = pwndbg.gdblib.argv.argc + 1

    if i is not None:
        n = 1
        start += (pwndbg.gdblib.arch.ptrsize) * i

    pwndbg.commands.telescope.telescope(start, n)


parser = argparse.ArgumentParser()
parser.description = "Prints out the contents of the environment."
parser.add_argument(
    "name", nargs="?", type=str, default=None, help="Name of the environment variable to see."
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["env", "environ"])
@pwndbg.commands.OnlyWhenRunning
def envp(name=None):
    if name is not None:
        gdb.execute('p $environ("%s")' % name)
        return
    """
    Prints out the contents of the environment.
    """
    start = pwndbg.gdblib.argv.envp
    n = pwndbg.gdblib.argv.envc + 1

    return pwndbg.commands.telescope.telescope(start, n)


class argv_function(gdb.Function):
    """
    Evaluate argv on the supplied value.
    """

    def __init__(self):
        super(argv_function, self).__init__("argv")

    def invoke(self, number=0):
        number = int(number)

        if number > pwndbg.gdblib.argv.argc:
            return 0

        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.argv)
        argv = value.cast(ppchar)
        return (argv + number).dereference()


argv_function()


class envp_function(gdb.Function):
    """
    Evaluate envp on the supplied value.
    """

    def __init__(self):
        super(envp_function, self).__init__("envp")

    def invoke(self, number=0):
        number = int(number)

        if number > pwndbg.gdblib.argv.envc:
            return pwndbg.gdblib.typeinfo.void

        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.envp)
        envp = value.cast(ppchar)
        return (envp + number).dereference()


envp_function()


class argc_function(gdb.Function):
    """
    Evaluates to argc.
    """

    def __init__(self):
        super(argc_function, self).__init__("argc")

    def invoke(self, number=0):
        return pwndbg.gdblib.argv.argc


argc_function()


class environ_function(gdb.Function):
    """
    Evaluate getenv() on the supplied value.
    """

    def __init__(self):
        super(environ_function, self).__init__("environ")

    def invoke(self, name):
        name = name.string() + "="
        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.envp)
        envp = value.cast(ppchar)

        for i in range(pwndbg.gdblib.argv.envc):
            ptr = (envp + i).dereference()
            sz = ptr.string()
            if sz.startswith(name):
                return ptr

        return pwndbg.gdblib.typeinfo.void


environ_function()
