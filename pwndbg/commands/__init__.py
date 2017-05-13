#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import abc
import argparse
import functools
import future.utils
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

debug = True


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
            if debug:
                print(traceback.format_exc())
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
            with pwndbg.stdio.stdio:
                return self.function(*args, **kwargs)
        except TypeError as te:
            print(te)
            print('%r: %s' % (self.function.__name__.strip(),
                              self.function.__doc__.strip()))
        except Exception:
            print(traceback.format_exc())


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

## TODO(pick an appropriate filename for these) Common types for argparse.add_argument(type=...), which will also be used for command completion

class ArgparseType(future.utils.with_metaclass(abc.ABCMeta)):
    @abc.abstractmethod
    def __call__(self, x): pass

    def do_complete(self, text, word, **kwargs):
        return gdb.COMPLETE_NONE

class ArgparseTypeInt(ArgparseType):
    def __call__(self, x):
        # eval $pc-10
        return x

    def do_complete(self, text, word, dest):
        return [dest]

class ArgparseTypeLocation(ArgparseType):
    def __call__(self, x):
        return x

    def do_complete(self, text, word, **kwargs):
        return gdb.COMPLETE_LOCATION


commands = []

class MetaCommand(type):
    def __init__(cls, name, bases, dct):
        commands.append(cls)
        return super().__init__(name, bases, dct)

class GenericCommand(future.utils.with_metaclass(MetaCommand, gdb.Command)):
    complete_type = -1
    prefix = False

    def __init__(self, *args, **kwargs):
        name = getattr(self, 'name', type(self).__name__)
        command_type = kwargs.setdefault("command", gdb.COMMAND_OBSCURE)

        self.parser = getattr(self, 'parser', None)
        if self.parser is None:
            pass
        elif isinstance(self.parser, argparse.ArgumentParser):
            self.parser.description = self.__doc__
        else:
            parser = self.parser
            self.parser = argparse.ArgumentParser(description=self.__doc__)
            for kw in parser:
                self.parser.add_argument(**kw)

        super().__init__(name, command_type, self.complete_type, self.prefix)

    def invoke(self, args, from_tty):
        try:
            args = gdb.string_to_argv(args)
            if self.parser is None:
                self.do_invoke(*args)
            else:
                try:
                    args = self.parser.parse_args(args)
                except SystemExit:
                    # If passing '-h' or '--help', argparse attempts to kill the process.
                    return
                self.do_invoke(**args.__dict__)
        except Exception as e:
            # TODO better error messages (`inspect` module) when arguments do not match parameters
            print('error' , type(e), e)

    def complete(self, text, word):
        if hasattr(self, 'do_complete'):
            try:
                return self.do_complete(text, word)
            except Exception as e:
                print('error' , type(e), e)
        else:
            positional = self.parser._get_positional_actions()
            text = gdb.string_to_argv(text)
            pos = len(text)
            if pos and word:
                pos -= 1
            if pos < len(positional):
                arg = positional[pos]
                if hasattr(arg.type, 'do_complete'):
                    return arg.type.do_complete(text, word, dest=arg.dest)
                else:
                    return [arg.dest]
            return []

    @abc.abstractmethod
    def do_invoke(self, **kwargs): pass


# TODO These are use cases

class aa(GenericCommand):
    complete_type = gdb.COMPLETE_FILENAME

    def do_invoke(self, argv):
        print('+aa', argv)

class bb(GenericCommand):
    """Document."""
    name = 'bb'
    parser = (
        dict(dest='address', nargs='?', default='$sp', help='hello'),
    )

    def do_invoke(self, address):
        print('+bb', address)

    def do_complete(self, text, word):
        #print('+bb complete', text, '++', word)
        return ['d']

class cc(GenericCommand):
    """Document."""
    parser = argparse.ArgumentParser()
    parser.add_argument('aaa', type=ArgparseTypeLocation())
    parser.add_argument('bbb', type=ArgparseTypeInt())

    def do_invoke(self, aaa, bbb):
        print('+cc', aaa, bbb)

class dd(GenericCommand):
    @OnlyWhenRunning
    def do_invoke(self):
        print('+dd')


# TODO(choose an appropriate file) Register all commands.

for cls in commands:
    cls()
