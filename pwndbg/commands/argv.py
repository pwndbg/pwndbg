#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.arch
import pwndbg.argv
import pwndbg.commands
import pwndbg.typeinfo


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def argc():
    """
    Prints out the number of arguments.
    """
    print(pwndbg.argv.argc)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def argv(i=None):
    """
    Prints out the contents of argv.
    """
    start = pwndbg.argv.argv
    n     = pwndbg.argv.argc+1

    if i is not None:
        n = 1
        start += (pwndbg.arch.ptrsize) * i

    pwndbg.commands.telescope.telescope(start, n)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def args():
    """
    Prints out the contents of argv.
    """
    argv()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def envp(name=None):
    """
    Prints out the contents of the environment.
    """
    start = pwndbg.argv.envp
    n     = pwndbg.argv.envc+1

    return pwndbg.commands.telescope.telescope(start, n)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def env(name=None):
    """
    Prints out the contents of the environment.
    """
    if name is None:
        return envp()

    gdb.execute('p $environ("%s")' % name)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def environ(name=None):
    """
    Prints out the contents of the environment.
    """
    if name is None:
        return envp()

    gdb.execute('p $environ("%s")' % name)

class argv_function(gdb.Function):
    """
    Evaluate argv on the supplied value.
    """
    def __init__(self):
        super(argv_function, self).__init__('argv')
    def invoke(self, number=0):
        number = int(number)

        if number > pwndbg.argv.argc:
            return 0

        ppchar = pwndbg.typeinfo.pchar.pointer()
        value  = gdb.Value(pwndbg.argv.argv)
        argv   = value.cast(ppchar)
        return((argv+number).dereference())

argv_function()


class envp_function(gdb.Function):
    """
    Evaluate envp on the supplied value.
    """
    def __init__(self):
        super(envp_function, self).__init__('envp')
    def invoke(self, number=0):
        number = int(number)

        if number > pwndbg.argv.envc:
            return pwndbg.typeinfo.void

        ppchar = pwndbg.typeinfo.pchar.pointer()
        value  = gdb.Value(pwndbg.argv.envp)
        envp   = value.cast(ppchar)
        return((envp+number).dereference())

envp_function()


class argc_function(gdb.Function):
    """
    Evaluates to argc.
    """
    def __init__(self):
        super(argc_function, self).__init__('argc')
    def invoke(self, number=0):
        return pwndbg.argv.argc

argc_function()


class environ_function(gdb.Function):
    """
    Evaluate getenv() on the supplied value.
    """
    def __init__(self):
        super(environ_function, self).__init__('environ')
    def invoke(self, name):
        name   = name.string() + '='
        ppchar = pwndbg.typeinfo.pchar.pointer()
        value  = gdb.Value(pwndbg.argv.envp)
        envp   = value.cast(ppchar)

        for i in range(pwndbg.argv.envc):
            ptr = (envp+i).dereference()
            sz  = ptr.string()
            if sz.startswith(name):
                return ptr

        return pwndbg.typeinfo.void

environ_function()
