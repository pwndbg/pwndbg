import argparse
import functools
import io
from typing import Dict
from typing import List

import gdb

import pwndbg.color.message as message
import pwndbg.exception
import pwndbg.gdblib.regs
import pwndbg.heap
from pwndbg.heap.ptmalloc import SymbolUnresolvableError

commands = []  # type: List[Command]
command_names = set()


def list_current_commands():
    current_pagination = gdb.execute("show pagination", to_string=True)
    current_pagination = current_pagination.split()[-1].rstrip(
        "."
    )  # Take last word and skip period

    gdb.execute("set pagination off")
    command_list = gdb.execute("help all", to_string=True).strip().split("\n")
    existing_commands = set()
    for line in command_list:
        line = line.strip()
        # Skip non-command entries
        if (
            len(line) == 0
            or line.startswith("Command class:")
            or line.startswith("Unclassified commands")
        ):
            continue
        command = line.split()[0]
        existing_commands.add(command)
    gdb.execute("set pagination %s" % current_pagination)  # Restore original setting
    return existing_commands


GDB_BUILTIN_COMMANDS = list_current_commands()


class Command(gdb.Command):
    """Generic command wrapper"""

    builtin_override_whitelist = {"up", "down", "search", "pwd", "start", "ignore"}
    history = {}  # type: Dict[int,str]

    def __init__(self, function, prefix=False, command_name=None, shell=False):
        self.shell = shell

        if command_name is None:
            command_name = function.__name__

        super(Command, self).__init__(
            command_name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION, prefix=prefix
        )
        self.function = function

        if command_name in command_names:
            raise Exception("Cannot add command %s: already exists." % command_name)
        if (
            command_name in GDB_BUILTIN_COMMANDS
            and command_name not in self.builtin_override_whitelist
        ):
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

        lines = gdb.execute("show commands", from_tty=False, to_string=True)
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
            print("%r: %s" % (self.function.__name__.strip(), self.function.__doc__.strip()))
            pwndbg.exception.handle(self.function.__name__)
        except Exception:
            pwndbg.exception.handle(self.function.__name__)


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
        arg = pwndbg.gdblib.regs.fix(arg)
        return gdb.parse_and_eval(arg)
    except Exception as e:
        if not quiet:
            print(e)
        if reraise:
            raise e

    if sloppy:
        return arg

    return None


def fix_int(*a, **kw):
    return int(fix(*a, **kw))


def fix_int_reraise(*a, **kw):
    return fix(*a, reraise=True, **kw)


def OnlyWithFile(function):
    @functools.wraps(function)
    def _OnlyWithFile(*a, **kw):
        if pwndbg.gdblib.proc.exe:
            return function(*a, **kw)
        else:
            if pwndbg.gdblib.qemu.is_qemu():
                print(message.error("Could not determine the target binary on QEMU."))
            else:
                print(message.error("%s: There is no file loaded." % function.__name__))

    return _OnlyWithFile


def OnlyWhenRunning(function):
    @functools.wraps(function)
    def _OnlyWhenRunning(*a, **kw):
        if pwndbg.gdblib.proc.alive:
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
            print(
                "%s: This version of GLIBC was not compiled with tcache support."
                % function.__name__
            )

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
    """Decorates function to work only when pwndbg.gdblib.arch.current == \"x86-64\"."""

    @functools.wraps(function)
    def _OnlyAmd64(*a, **kw):
        if pwndbg.gdblib.arch.current == "x86-64":
            return function(*a, **kw)
        else:
            print('%s: Only works with "x86-64" arch.' % function.__name__)

    return _OnlyAmd64


# TODO/FIXME: Move this elsewhere? Have better logic for that? Maybe caching?
def _is_statically_linked():
    out = gdb.execute("info dll", to_string=True)
    return "No shared libraries loaded at this time." in out


def OnlyWithResolvedHeapSyms(function):
    @functools.wraps(function)
    def _OnlyWithResolvedHeapSyms(*a, **kw):
        e = lambda s: print(message.error(s))
        w = lambda s: print(message.warn(s))
        if pwndbg.heap.current.can_be_resolved():
            # Note: We will still raise the error for developers when exception-* is set to "on"
            try:
                return function(*a, **kw)
            except SymbolUnresolvableError as err:
                e(f"{function.__name__}: Fail to resolve the symbol: `{err.symbol}`")
                w(
                    f"You can try to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap_config` command output and set the config about `{err.symbol}`."
                )
                if (
                    pwndbg.gdblib.config.exception_verbose
                    or pwndbg.gdblib.config.exception_debugger
                ):
                    raise err
                else:
                    pwndbg.exception.inform_verbose_and_debug()
            except Exception as err:
                e(f"{function.__name__}: An unknown error occurred when running this command.")
                if pwndbg.gdblib.config.resolve_heap_via_heuristic:
                    w(
                        "Maybe you can try to determine the libc symbols addresses manually, set them appropriately and re-run this command. For this, see the `heap_config` command output and set the `main_arena`, `mp_`, `global_max_fast`, `tcache` and `thread_arena` addresses."
                    )
                else:
                    w("You can try `set resolve-heap-via-heuristic on` and re-run this command.\n")
                if (
                    pwndbg.gdblib.config.exception_verbose
                    or pwndbg.gdblib.config.exception_debugger
                ):
                    raise err
                else:
                    pwndbg.exception.inform_verbose_and_debug()
        else:
            print(message.error(f"{function.__name__}: "), end="")
            if not pwndbg.gdblib.config.resolve_heap_via_heuristic:
                if _is_statically_linked():
                    e(
                        "Can't find libc symbols addresses required for this command to work since this is a statically linked binary"
                    )
                    w(
                        """Invoking the `set resolve-heap-via-heuristic on` command to resolve libc symbols via heuristics.
Please set the GLIBC version you think the target binary was compiled (using `set glibc <version>` command; e.g. 2.32) and re-run this command.
If this does not work, the only thing left is to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap_config` command output and set the `main_arena`, `mp_`, `global_max_fast`, `tcache` and `thread_arena` addresses."""
                    )
                    gdb.execute("set resolve-heap-via-heuristic on", to_string=True)
                    return

                else:

                    w(
                        """This command only works with libc debug symbols which are missing.

They can probably be installed via the package manager of your choice.
See also: https://sourceware.org/gdb/onlinedocs/gdb/Separate-Debug-Files.html

E.g. on Ubuntu/Debian you might need to do the following steps (for 64-bit and 32-bit binaries):
sudo apt-get install libc6-dbg
sudo dpkg --add-architecture i386
sudo apt-get install libc-dbg:i386

If you used setup.sh on Arch based distro you'll need to do a power cycle or set environment variable manually like this: export DEBUGINFOD_URLS=https://debuginfod.archlinux.org
"""
                    )
                    w(
                        "pwndbg can still try to use this command without debug symbols after you `set resolve-heap-via-heuristic on`, but the results of those commands may be incorrect in some cases.\n"
                        "If the output of the heap command is still wrong or gives you erros, the only thing left is to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap_config` command output and set the `main_arena`, `mp_`, `global_max_fast`, `tcache` and `thread_arena` addresses."
                    )
            elif pwndbg.glibc.get_version() is None:
                e("Can't resolve the heap since the GLIBC version is not set.")
                w(
                    "Please set the GLIBC version you think the target binary was compiled (using `set glibc <version>` command; e.g. 2.32) and re-run this command."
                )
            else:
                e("An unknown error occurred when resolved the heap.")
                pwndbg.exception.inform_report_issue(
                    "An unknown error occurred when resolved the heap"
                )

    return _OnlyWithResolvedHeapSyms


class _ArgparsedCommand(Command):
    def __init__(self, parser, function, command_name=None, *a, **kw):
        self.parser = parser
        if command_name is None:
            self.parser.prog = function.__name__
        else:
            self.parser.prog = command_name

        file = io.StringIO()
        self.parser.print_help(file)
        file.seek(0)
        self.__doc__ = file.read()
        # Note: function.__doc__ is used in the `pwndbg [filter]` command display
        function.__doc__ = self.parser.description.strip()

        super(_ArgparsedCommand, self).__init__(function, command_name=command_name, *a, **kw)

    def split_args(self, argument):
        argv = gdb.string_to_argv(argument)
        return tuple(), vars(self.parser.parse_args(argv))


class ArgparsedCommand:
    """Adds documentation and offloads parsing for a Command via argparse"""

    def __init__(self, parser_or_desc, aliases=[], command_name=None):
        """
        :param parser_or_desc: `argparse.ArgumentParser` instance or `str`
        """
        if isinstance(parser_or_desc, str):
            self.parser = argparse.ArgumentParser(description=parser_or_desc)
        else:
            self.parser = parser_or_desc
        self.aliases = aliases
        self._command_name = command_name

        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        for action in self.parser._actions:
            if action.dest == "help":
                continue
            if action.type in (int, None):
                action.type = fix_int_reraise
            if action.default is not None:
                action.help += " (default: %(default)s)"

    def __call__(self, function):
        for alias in self.aliases:
            _ArgparsedCommand(self.parser, function, command_name=alias)
        return _ArgparsedCommand(self.parser, function, command_name=self._command_name)


# We use a 64-bit max value literal here instead of pwndbg.gdblib.arch.current
# as realistically its ok to pull off the biggest possible type here
# We cache its GDB value type which is 'unsigned long long'
_mask = 0xFFFFFFFFFFFFFFFF
_mask_val_type = gdb.Value(_mask).type


def sloppy_gdb_parse(s):
    """
    This function should be used as ``argparse.ArgumentParser`` .add_argument method's `type` helper.

    This makes the type being parsed as gdb value and if that parsing fails,
    a string is returned.

    :param s: String.
    :return: Whatever gdb.parse_and_eval returns or string.
    """
    try:
        val = gdb.parse_and_eval(s)
        # We can't just return int(val) because GDB may return:
        # "Python Exception <class 'gdb.error'> Cannot convert value to long."
        # e.g. for:
        # pwndbg> pi int(gdb.parse_and_eval('__libc_start_main'))
        #
        # Here, the _mask_val.type should be `unsigned long long`
        return int(val.cast(_mask_val_type))
    except (TypeError, gdb.error):
        return s


def AddressExpr(s):
    """
    Parses an address expression. Returns an int.
    """
    val = sloppy_gdb_parse(s)

    if not isinstance(val, int):
        raise argparse.ArgumentError("Incorrect address (or GDB expression): %s" % s)

    return val


def HexOrAddressExpr(s):
    """
    Parses string as hexadecimal int or an address expression. Returns an int.
    (e.g. '1234' will return 0x1234)
    """
    try:
        return int(s, 16)
    except ValueError:
        return AddressExpr(s)


def load_commands():
    import pwndbg.commands.argv
    import pwndbg.commands.aslr
    import pwndbg.commands.attachp
    import pwndbg.commands.auxv
    import pwndbg.commands.canary
    import pwndbg.commands.checksec
    import pwndbg.commands.comments
    import pwndbg.commands.config
    import pwndbg.commands.context
    import pwndbg.commands.cpsr
    import pwndbg.commands.cyclic
    import pwndbg.commands.cymbol
    import pwndbg.commands.dt
    import pwndbg.commands.dumpargs
    import pwndbg.commands.elf
    import pwndbg.commands.flags
    import pwndbg.commands.gdbinit
    import pwndbg.commands.ghidra
    import pwndbg.commands.got
    import pwndbg.commands.heap
    import pwndbg.commands.hexdump
    import pwndbg.commands.ida
    import pwndbg.commands.ignore
    import pwndbg.commands.ipython_interactive
    import pwndbg.commands.leakfind
    import pwndbg.commands.memoize
    import pwndbg.commands.misc
    import pwndbg.commands.mprotect
    import pwndbg.commands.next
    import pwndbg.commands.p2p
    import pwndbg.commands.patch
    import pwndbg.commands.peda
    import pwndbg.commands.pie
    import pwndbg.commands.probeleak
    import pwndbg.commands.procinfo
    import pwndbg.commands.radare2
    import pwndbg.commands.reload
    import pwndbg.commands.rop
    import pwndbg.commands.ropper
    import pwndbg.commands.search
    import pwndbg.commands.segments
    import pwndbg.commands.shell
    import pwndbg.commands.stack
    import pwndbg.commands.start
    import pwndbg.commands.telescope
    import pwndbg.commands.tls
    import pwndbg.commands.version
    import pwndbg.commands.vmmap
    import pwndbg.commands.windbg
    import pwndbg.commands.xinfo
    import pwndbg.commands.xor
