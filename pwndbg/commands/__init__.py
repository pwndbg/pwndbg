#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import functools

import gdb

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
command_names = set()

def list_current_commands():
    current_pagination = gdb.execute('show pagination', to_string=True)
    current_pagination = current_pagination.split()[-1].rstrip('.')  # Take last word and skip period

    gdb.execute('set pagination off')
    command_list = gdb.execute('help all', to_string=True).strip().split('\n')
    existing_commands = set()
    for line in command_list:
        line = line.strip()
        # Skip non-command entries
        if len(line) == 0 or line.startswith('Command class:') or line.startswith('Unclassified commands'):
            continue
        command = line.split()[0]
        existing_commands.add(command)
    gdb.execute('set pagination %s' % current_pagination) # Restore original setting
    return existing_commands

GDB_BUILTIN_COMMANDS = list_current_commands()

class Command(gdb.Command):
    """Generic command wrapper"""
    builtin_override_whitelist = {'up', 'down', 'search', 'pwd', 'start'}
    history = {}

    def __init__(self, function, prefix=False, command_name=None):
        if command_name is None:
            command_name = function.__name__

        super(Command, self).__init__(command_name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION, prefix=prefix)
        self.function = function

        if command_name in command_names:
            raise Exception('Cannot add command %s: already exists.' % command_name)
        if command_name in GDB_BUILTIN_COMMANDS and command_name not in self.builtin_override_whitelist:
            raise Exception('Cannot override non-whitelisted built-in command "%s"' % command_name)

        command_names.add(command_name)
        commands.append(self)

        functools.update_wrapper(self, function)
        self.__name__ = command_name

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
        try:
            number = int(number)
        except ValueError:
            # Workaround for a GDB 8.2 bug when show commands return error value
            # See issue #523
            return False

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

def OnlyWithTcache(function):
    @functools.wraps(function)
    def _OnlyWithTcache(*a, **kw):
        if pwndbg.heap.current.has_tcache():
            return function(*a, **kw)
        else:
            print("%s: This version of GLIBC was not compiled with tcache support." % function.__name__)
    return _OnlyWithTcache

def OnlyWhenHeapIsInitialized(function):
    @functools.wraps(function)
    def _OnlyWhenHeapIsInitialized(*a, **kw):
        if pwndbg.heap.current.is_initialized():
            return function(*a, **kw)
        else:
            print("%s: Heap is not initialized yet." % function.__name__)
    return _OnlyWhenHeapIsInitialized

def OnlyAmd64(function):
    """Decorates function to work only when pwndbg.arch.current == \"x86-64\".
    """
    @functools.wraps(function)
    def _OnlyAmd64(*a, **kw):
        if pwndbg.arch.current == "x86-64":
            return function(*a, **kw)
        else:
            print("%s: Only works with \"x86-64\" arch." % function.__name__)
    return _OnlyAmd64

def OnlyWithLibcDebugSyms(function):
    @functools.wraps(function)
    def _OnlyWithLibcDebugSyms(*a, **kw):
        if pwndbg.heap.current.libc_has_debug_syms():
            return function(*a, **kw)
        else:
            print('''%s: This command only works with libc debug symbols.
They can probably be installed via the package manager of your choice.
See also: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

E.g. on Ubuntu/Debian you might need to do the following steps (for 64-bit and 32-bit binaries):
sudo apt-get install libc6-dbg
sudo dpkg --add-architecture i386
sudo apt-get install libc-dbg:i386
''' % function.__name__)
    return _OnlyWithLibcDebugSyms

class QuietSloppyParsedCommand(ParsedCommand):
    def __init__(self, *a, **kw):
        super(QuietSloppyParsedCommand, self).__init__(*a, **kw)
        self.quiet = True
        self.sloppy = True


class _ArgparsedCommand(Command):
    def __init__(self, parser, function, command_name=None, *a, **kw):
        self.parser = parser
        if command_name is None:
            self.parser.prog = function.__name__
        else:
            self.parser.prog = command_name
        self.__doc__ = function.__doc__ = self.parser.description.strip()
        super(_ArgparsedCommand, self).__init__(function, command_name=command_name, *a, **kw)

    def split_args(self, argument):
        argv = gdb.string_to_argv(argument)
        return tuple(), vars(self.parser.parse_args(argv))


class ArgparsedCommand:
    """Adds documentation and offloads parsing for a Command via argparse"""
    def __init__(self, parser_or_desc, aliases=[]):
        """
        :param parser_or_desc: `argparse.ArgumentParser` instance or `str`
        """
        if isinstance(parser_or_desc, str):
            self.parser = argparse.ArgumentParser(description=parser_or_desc)
        else:
            self.parser = parser_or_desc
        self.aliases = aliases
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
        for alias in self.aliases:
            _ArgparsedCommand(self.parser, function, alias)
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
