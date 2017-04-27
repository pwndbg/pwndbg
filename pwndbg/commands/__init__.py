#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pdb
import functools
import traceback

import gdb

import pwndbg.chain
import pwndbg.color
import pwndbg.enhance
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs
import pwndbg.stdio
import pwndbg.symbol
import pwndbg.ui


verbose = pwndbg.config.Parameter('exception-verbose', False, 'whether to print a full stacktracefor exceptions raised in Pwndbg commands')
debug = pwndbg.config.Parameter('exception-debugger', False, 'whether to debug exceptions raised in Pwndbg commands')

def handle_exception():
    if debug or verbose:
        print(traceback.format_exc())
    if debug:
        with pwndbg.stdio.stdio:
            pdb.post_mortem()


class _Command(gdb.Command):
    """Generic command wrapper"""
    count    = 0
    commands = []
    history  = {}

    def __init__(self, function, inc=True, prefix=False):
        super(_Command, self).__init__(function.__name__, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION, prefix=prefix)
        self.function = function

        if inc:
            self.commands.append(self)

        functools.update_wrapper(self, function)
        self.__doc__ = function.__doc__

    def split_args(self, argument):
        return gdb.string_to_argv(argument)

    def invoke(self, argument, from_tty):
        argv = self.split_args(argument)
        try:
            self.repeat = self.check_repeated(argument, from_tty)
            return self(*argv)
        except TypeError:
            handle_exception()
            raise
        finally:
            self.repeat = False

    def check_repeated(self, argument, from_tty):
        """Keep a record of all commands which come from the TTY.

        Returns:
            True if this command was executed by the user just hitting "enter".
        """
        # Don't care unless it's interactive use
        if not from_tty:
            return False

        lines = gdb.execute('show commands', from_tty=False, to_string=True)
        lines = lines.splitlines()

        # No history
        if not lines:
            return False

        last_line = lines[-1]
        number, command = last_line.split(None, 1)
        number = int(number)

        # A new command was entered by the user
        if number not in _Command.history:
            _Command.history[number] = command
            return False

        # Somehow the command is different than we got before?
        if not command.endswith(argument):
            return False

        return True

    def __call__(self, *args, **kwargs):
        try:
            return self.function(*args, **kwargs)
        except TypeError as te:
            print(te)
            print('%r: %s' % (self.function.__name__.strip(),
                              self.function.__doc__.strip()))
            handle_exception()
        except Exception:
            handle_exception()


class _ParsedCommand(_Command):
    #: Whether to return the string 'arg' if parsing fails.
    sloppy = False

    #: Whether to hide errors during parsing
    quiet  = False

    def split_args(self, argument):
        # sys.stdout.write(repr(argument) + '\n')
        argv = super(_ParsedCommand,self).split_args(argument)
        # sys.stdout.write(repr(argv) + '\n')
        return list(filter(lambda x: x is not None, map(self.fix, argv)))

    def fix(self, arg):
        return fix(arg, self.sloppy, self.quiet)


class _ParsedCommandPrefix(_ParsedCommand):
    def __init__(self, function, inc=True, prefix=True):
        super(_ParsedCommand, self).__init__(function, inc, prefix)


def fix(arg, sloppy=False, quiet=True):
    if isinstance(arg, gdb.Value):
        return arg

    try:
        parsed = gdb.parse_and_eval(arg)
        return parsed
    except Exception:
        pass

    try:
        arg = pwndbg.regs.fix(arg)
        return gdb.parse_and_eval(arg)
    except Exception as e:
        if not quiet:
            print(e)
        pass

    if sloppy:
        return arg

    return None


def fix_int(*a, **kw):
    return int(fix(*a,**kw))


def OnlyWithFile(function):
    @functools.wraps(function)
    def _OnlyWithFile(*a, **kw):
        if pwndbg.proc.exe:
            return function(*a, **kw)
        else:
            print("There is no file loaded.")

    return _OnlyWithFile


def OnlyWhenRunning(function):
    @functools.wraps(function)
    def _OnlyWhenRunning(*a, **kw):
        if pwndbg.proc.alive:
            return function(*a, **kw)
        else:
            print("The program is not being run.")
    return _OnlyWhenRunning


def Command(func, *a, **kw):
    class C(_Command):
        __doc__ = func.__doc__
        __name__ = func.__name__
    return C(func, *a, **kw)


def ParsedCommand(func):
    class C(_ParsedCommand):
        __doc__ = func.__doc__
        __name__ = func.__name__
    return C(func)


def QuietSloppyParsedCommand(func):
    c = ParsedCommand(func)
    c.quiet = True
    c.sloppy = True
    return c


class ArgparsedCommand(object):
    """Adds documentation and offloads parsing for a Command via argparse"""
    def __init__(self, parser):
        self.parser = parser

        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        for action in parser._actions:
            if action.dest == 'help':
                continue
            if action.type in (int, None):
                action.type = fix_int
            if action.default is not None:
                action.help += ' (default: %(default)s)'

    def __call__(self, function):
        self.parser.prog = function.__name__

        @functools.wraps(function)
        def _ArgparsedCommand(*args):
            try:
                args = self.parser.parse_args(args)
            except SystemExit:
                # If passing '-h' or '--help', argparse attempts to kill the process.
                return
            return function(**vars(args))
        _ArgparsedCommand.__doc__ = self.parser.description
        return Command(_ArgparsedCommand)
