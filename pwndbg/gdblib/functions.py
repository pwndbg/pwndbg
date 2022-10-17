"""
Put all functions defined for gdb in here.

This file might be changed into a module in the future.
"""

import functools

import gdb

import pwndbg.gdblib.proc

functions = []


def GdbFunction(only_when_running=False):
    return functools.partial(_GdbFunction, only_when_running=only_when_running)


class _GdbFunction(gdb.Function):
    def __init__(self, func, only_when_running):
        self.name = func.__name__
        self.func = func
        self.only_when_running = only_when_running

        functions.append(self)

        super(_GdbFunction, self).__init__(self.name)

        functools.update_wrapper(self, func)
        self.__doc__ = func.__doc__

    def invoke(self, *args):
        if self.only_when_running and not pwndbg.gdblib.proc.alive:
            # Returning empty string is a workaround that we can't stop e.g. `break *$rebase(offset)`
            # Thx to that, gdb will print out 'evaluation of this expression requires the target program to be active'
            return ""

        return self.func(*args)

    def __call__(self, *args):
        return self.invoke(*args)


@GdbFunction(only_when_running=True)
def rebase(addr):
    """Return rebased address."""
    base = pwndbg.gdblib.elf.exe().address
    return base + int(addr)
