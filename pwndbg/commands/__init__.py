#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import functools

import gdb
import six

import pwndbg.chain
import pwndbg.color
import pwndbg.enhance
import pwndbg.exception
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs
import pwndbg.symbol
import pwndbg.ui

commands = []


class Command(gdb.Command):
    """Generic command wrapper"""
    command_names = set()
    history = {}

    def __init__(self, function, prefix=False):
        command_name = function.__name__

        super(Command, self).__init__(command_name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION, prefix=prefix)
        self.function = function

        if command_name in self.command_names:
            raise Exception('Cannot add command %s: already exists.' % command_name)

        self.command_names.add(command_name)
        commands.append(self)

        functools.update_wrapper(self, function)
        self.__doc__ = function.__doc__

        self.repeat = False

    def split_args(self, argument):
        """Split a command-line string from the user into arguments.

        Returns:
            A ``(tuple, dict)``, in the form of ``*args, **kwargs``.
            The contents of the tuple/dict are undefined.
        """
        return gdb.string_to_argv(argument), {}

    def invoke(self, argument, from_tty):
        """Invoke the command with an argument string"""
        try:
            args, kwargs = self.split_args(argument)
        except SystemExit:
            # Raised when the usage is printed by an ArgparsedCommand
            return
        except (TypeError, gdb.error):
            pwndbg.exception.handle(self.function.__name__)
            return

        try:
            self.repeat = self.check_repeated(argument, from_tty)
            return self(*args, **kwargs)
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
        if number not in Command.history:
            Command.history[number] = command
            return False

        # Somehow the command is different than we got before?
        if not command.endswith(argument):
            return False

        return True

    def __call__(self, *args, **kwargs):
        try:
            return self.function(*args, **kwargs)
        except TypeError as te:
            print('%r: %s' % (self.function.__name__.strip(),
                              self.function.__doc__.strip()))
            pwndbg.exception.handle(self.function.__name__)
        except Exception:
            pwndbg.exception.handle(self.function.__name__)


class ParsedCommand(Command):
    #: Whether to return the string 'arg' if parsing fails.
    sloppy = False

    #: Whether to hide errors during parsing
    quiet  = False

    def split_args(self, argument):
        # sys.stdout.write(repr(argument) + '\n')
        argv, _ = super(ParsedCommand, self).split_args(argument)
        # sys.stdout.write(repr(argv) + '\n')
        return list(filter(lambda x: x is not None, map(self.fix, argv))), {}

    def fix(self, arg):
        return fix(arg, self.sloppy, self.quiet)


class ParsedCommandPrefix(ParsedCommand):
    def __init__(self, function, prefix=True):
        super(ParsedCommand, self).__init__(function, prefix)


def fix(arg, sloppy=False, quiet=True, reraise=False):
    """Fix a single command-line argument coming from the GDB CLI.

    Arguments:
        arg(str): Original string representation (e.g. '0', '$rax', '$rax+44')
        sloppy(bool): If ``arg`` cannot be evaluated, return ``arg``. (default: False)
        quiet(bool): If an error occurs, suppress it. (default: True)
        reraise(bool): If an error occurs, raise the exception. (default: False)

    Returns:
        Ideally ``gdb.Value`` object.  May return a ``str`` if ``sloppy==True``.
        May return ``None`` if ``sloppy == False and reraise == False``.
    """
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
        if reraise:
            raise e
        pass

    if sloppy:
        return arg

    return None


def fix_int(*a, **kw):
    return int(fix(*a,**kw))

def fix_int_reraise(*a, **kw):
    return fix(*a, reraise=True, **kw)


def OnlyWithFile(function):
    @functools.wraps(function)
    def _OnlyWithFile(*a, **kw):
        if pwndbg.proc.exe:
            return function(*a, **kw)
        else:
            print("%s: There is no file loaded." % function.__name__)

    return _OnlyWithFile


def OnlyWhenRunning(function):
    @functools.wraps(function)
    def _OnlyWhenRunning(*a, **kw):
        if pwndbg.proc.alive:
            return function(*a, **kw)
        else:
            print("%s: The program is not being run." % function.__name__)
    return _OnlyWhenRunning

def OnlyWhenHeapIsInitialized(function):
    @functools.wraps(function)
    def _OnlyWhenHeapIsInitialized(*a, **kw):
        if pwndbg.heap.current.is_initialized():
            return function(*a, **kw)
        else:
            print("%s: Heap is not initialized yet." % function.__name__)
    return _OnlyWhenHeapIsInitialized


class QuietSloppyParsedCommand(ParsedCommand):
    def __init__(self, *a, **kw):
        super(QuietSloppyParsedCommand, self).__init__(*a, **kw)
        self.quiet = True
        self.sloppy = True


class _ArgparsedCommand(Command):
    def __init__(self, parser, function, *a, **kw):
        self.parser = parser
        self.parser.prog = function.__name__
        self.__doc__ = function.__doc__ = self.parser.description
        super(_ArgparsedCommand, self).__init__(function, *a, **kw)

    def split_args(self, argument):
        argv = gdb.string_to_argv(argument)
        return tuple(), vars(self.parser.parse_args(argv))


class ArgparsedCommand(object):
    """Adds documentation and offloads parsing for a Command via argparse"""
    def __init__(self, parser_or_desc):
        """
        :param parser_or_desc: `argparse.ArgumentParser` instance or `str`
        """
        if isinstance(parser_or_desc, six.string_types):
            self.parser = argparse.ArgumentParser(description=parser_or_desc)
        else:
            self.parser = parser_or_desc

        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        for action in self.parser._actions:
            if action.dest == 'help':
                continue
            if action.type in (int, None):
                action.type = fix_int_reraise
            if action.default is not None:
                action.help += ' (default: %(default)s)'

    def __call__(self, function):
        return _ArgparsedCommand(self.parser, function)


def sloppy_gdb_parse(s):
    """
    This function should be used as ``argparse.ArgumentParser`` .add_argument method's `type` helper.
    
    This makes the type being parsed as gdb value and if that parsing fails,
    a string is returned.

    :param s: String.
    :return: Whatever gdb.parse_and_eval returns or string.
    """
    try:
        return gdb.parse_and_eval(s)
    except (TypeError, gdb.error):
        return s
