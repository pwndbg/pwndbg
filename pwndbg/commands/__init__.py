"""
Pwndbg command implementations.

As well as various command-handling logic.
"""

from __future__ import annotations

import argparse
import functools
import logging
from collections.abc import Callable
from enum import Enum
from typing import Any
from typing import TypeVar

from typing_extensions import ParamSpec
from typing_extensions import override

import pwndbg.aglib
import pwndbg.aglib.heap
import pwndbg.aglib.kernel
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.symbol
import pwndbg.dbg_mod
import pwndbg.dintegration
import pwndbg.exception
import pwndbg.libc
from pwndbg.aglib.heap.ptmalloc import DebugSymsHeap
from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator
from pwndbg.aglib.heap.ptmalloc import HeuristicHeap
from pwndbg.color import message
from pwndbg.lib import SymbolNotRecoveredError
from pwndbg.lib import TypeNotRecoveredError

log = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")

commands: list[CommandObj] = []
command_names: set[str] = set()


class CommandCategory(str, Enum):
    START = "Start"
    NEXT = "Step/Next/Continue"
    CONTEXT = "Context"
    PTMALLOC2 = "GLibc ptmalloc2 Heap"
    ALLOCATORS = "Allocators"
    BREAKPOINT = "Breakpoint"
    MEMORY = "Memory"
    STACK = "Stack"
    REGISTER = "Register"
    PROCESS = "Process"
    LINUX = "Linux/libc/ELF"
    DARWIN = "Darwin/libsystem/Mach-O"
    DISASS = "Disassemble"
    MISC = "Misc"
    KERNEL = "Kernel"
    INTEGRATIONS = "Integrations"
    WINDBG = "WinDbg"
    PWNDBG = "Pwndbg"
    SHELL = "Shell"
    DEV = "Developer"


GDB_BUILTIN_COMMANDS = pwndbg.dbg.commands()

# Set in `reload` command so that we can skip double checking for registration
# of an already existing command when re-registering GDB CLI commands
# (there is no way to unregister a command in GDB 12.x)
pwndbg_is_reloading = False
if pwndbg.dbg.is_gdblib_available():
    import gdb

    pwndbg_is_reloading = getattr(gdb, "pwndbg_is_reloading", False)


class InvalidDebuggerError(Exception):
    """
    Raised when a command is called in a debugger for which
    it is disallowed.
    """


class CommandFormatter(argparse.RawDescriptionHelpFormatter):
    """
    The formatter_class that is passed to argparse for all
    commands.

    Subclassing this isn't officially supported, but there
    isn't a good alternative.
    """

    @override
    def format_help(self) -> str:
        """
        Formats the help string to reorder it, so that its first description line is first
        and the usage string is second. This means we change the help from:
            usage: command [-flags]

            First line description

            positional arguments: (... etc)

        To:
            First line description

            usage: command [-flags]

            positional arguments: (... etc)

        We do this for GDB as it takes the first line of command help for its 'apropos <cmd>' command.
        See #3502 for more information.
        """

        # Do this only if there are at least two items
        if len(self._root_section.items) >= 2:
            self._root_section.items[0], self._root_section.items[1] = (
                self._root_section.items[1],
                self._root_section.items[0],
            )

        return super().format_help()

    @override
    def _get_help_string(self, action: argparse.Action) -> str:
        # Yoinked from argparse.ArgumentDefaultsHelpFormatter with
        # the added ` and action.default not in (None, False)` check.
        help_ = action.help
        if help_ is None:
            help_ = ""

        if "%(default)" not in help_:
            is_false_bool = (
                action.type is bool or isinstance(action.default, bool)
            ) and not action.default
            is_none = action.default is None
            if action.default is not argparse.SUPPRESS and not (is_false_bool or is_none):
                defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
                if action.option_strings or action.nargs in defaulting_nargs:
                    if action.type is str:
                        help_ += " (default: '%(default)s')"
                    else:
                        help_ += " (default: %(default)s)"

        return help_


class CommandObj:
    """
    Represents a command that can be invoked from the
    debugger.
    """

    builtin_override_whitelist: set[str] = {
        "up",
        "down",
        "search",
        "pwd",
        "start",
        "starti",
        "ignore",
    }
    history: dict[int, str] = {}

    def __init__(
        self,
        function: Callable[..., str | None],
        parser: argparse.ArgumentParser,
        command_name: str | None,
        category: CommandCategory,
        aliases: list[str],
        examples: str,
        notes: str,
        /,  # All parameters must be passed in positionally
    ) -> None:
        assert function
        self.function: Callable[..., str | None] = function

        if command_name is None:
            # Take the command name from the name of the function
            # which defines it, but replace '_' with '-'.
            self.command_name: str = function.__name__.replace("_", "-")
        else:
            self.command_name = command_name

        assert "_" not in self.command_name and "Use '-' instead of '_' in command names."
        assert self.command_name not in command_names and "Command already exists."
        assert (
            not (
                self.command_name in GDB_BUILTIN_COMMANDS
                and self.command_name not in CommandObj.builtin_override_whitelist
                and not pwndbg_is_reloading
            )
            and "Cannot override non-whitelisted built-in command."
        )

        assert category
        self.category: CommandCategory = category

        self.aliases: list[str] = aliases
        self.examples: str = examples.strip()
        self.notes: str = notes.strip()

        assert parser
        self.parser: argparse.ArgumentParser = parser
        # Sets self.help_str, self.description and self.subcommand_names (among other stuff).
        self.help_str: str
        self.description: str
        self.subcommand_names: list[str] | None
        self.initialize_parser()

        # Let the debugger and pwndbg global state know about it.
        self.register_command()

        # For commands like hexdump where you get new output from
        # continuous invocations.
        self.repeat: bool = False

    def register_command(self) -> None:
        """
        Register this object command with the underlying debugger
        and update pwndbg global state to know about this command.
        """

        def _handler(
            _debugger: pwndbg.dbg_mod.Debugger, arguments: str, is_interactive: bool
        ) -> None:
            self.invoke(arguments, is_interactive)

        if self.subcommand_names is not None and len(self.subcommand_names) > 0:
            # In order to add `help <main> <sub>` support, the main
            # command needs to be registered as a prefix command in
            # GDB. Since this causes help info duplication, for now
            # we simply show a hint to use `--help`
            potential_newline: str = "" if self.aliases else "\n"
            self.help_str += f"{potential_newline}Hint: Use `{self.command_name} <subcmd> --help` if you want to see subcommand information."

        # Keep a handle to the command and its aliases so we can
        # easily remove them if necessary (not supported with GDB).
        self.handles = [
            # Tell the debugger about the command...
            pwndbg.dbg.add_command(
                self.command_name, _handler, self.help_str, self.subcommand_names
            )
        ]

        # ...and all of its aliases.
        self.handles.extend(
            pwndbg.dbg.add_command(alias, _handler, self.help_str, self.subcommand_names)
            for alias in self.aliases
        )

        command_names.add(self.command_name)
        commands.append(self)

    @staticmethod
    def has_notes_string(text: str) -> bool:
        return any(nt in text.lower() for nt in ("note:", "notes:"))

    @staticmethod
    def has_examples_string(text: str) -> bool:
        return any(ex in text.lower() for ex in ("example:", "examples:"))

    def setup_epilog(self) -> None:
        # Build the actual epilog from the examples, notes and passed epilog.
        self.epilog = ""
        self.pure_epilog = ""

        if self.examples:
            assert (
                not self.has_examples_string(self.examples)
                and "No need, `Examples:` is added automatically."
            )
            # Not putting '\n' in the notice() so .strip() works properly.
            self.epilog += "\n" + message.notice("Examples:") + "\n"
            self.epilog += self.examples + "\n"

        if self.notes:
            assert (
                not self.has_notes_string(self.notes)
                and "No need, `Notes:` is added automatically."
            )
            self.epilog += "\n" + message.notice("Notes:") + "\n"
            self.epilog += self.notes + "\n"

        if self.parser.epilog:
            self.pure_epilog = self.parser.epilog.strip()
            assert (
                not self.has_examples_string(self.pure_epilog)
                and "Put examples into pwndbg.commands.Command(examples=your_example)."
            )
            assert (
                not self.has_notes_string(self.pure_epilog)
                and "Put notes into pwndbg.commands.Command(notes=your_note)."
            )
            self.epilog += "\n" + self.pure_epilog + "\n"

        if self.aliases:
            alias_txt = "Alias" + ("es" if len(self.aliases) > 1 else "") + ": "
            self.epilog += "\n" + message.notice(alias_txt)
            self.epilog += ", ".join(self.aliases) + "\n"

        # Update the parser so the help is correctly generated.
        self.parser.epilog = self.epilog = self.epilog.strip()

    @staticmethod
    def initialize_parser_recursively(
        parser: argparse.ArgumentParser, top_level_name: str, level: int
    ) -> None:
        if level == 0:
            # Top level command
            assert parser.prog[0] != " "
            assert top_level_name == ""
        else:
            # Workaround until https://github.com/pwndbg/pwndbg/issues/3523
            # is fixed.
            parser.prog = (
                parser.prog.replace("pwndbg-lldb", "")
                .replace("launch_guest.py", "")
                .replace("python3 -m tests.host.lldb.launch_guest", "")
            )
            # A level one subcommand will have parser.prog == " install"
            # while a level two subcommand will have parser.prog == "install ida".
            # Except on lldb, where its " install ida" (after the replace).
            # How does this make sense? So annoying..
            assert top_level_name != ""
            if level == 1:
                assert parser.prog[0] == " ", (
                    "Pwndbg automatically sets the subparser's prog. Don't touch it, just set the name."
                )
            else:
                parser.prog = parser.prog.strip()
                assert parser.prog.count(" ") == level - 1, (
                    "Pwndbg automatically sets the subparser's prog. Don't touch it, just set the name."
                )
                parser.prog = " " + parser.prog

        parser.prog = top_level_name + parser.prog

        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        for action in parser._actions:
            if action.dest == "help":
                # The HelpAction exists by default and handles `-h` and `--help`.
                # No need to do anything about it.
                continue

            if not isinstance(action, argparse._SubParsersAction) and action.help is None:
                # When we do `cmd -h` we want each argument to have a one-line
                # description.
                # Unfortunately, I don't know how to enforce that each subcommand has a help=
                # passed to its add_parser() :(
                print(message.error(f"Error parsing arguments for command: {parser.prog}"))
                print("You must add a `help=` string to your argument.")
                print(f"Erroneous action:\n\t{repr(action)}\n")
                assert False, "You must add a `help=` string to your argument."

            if action.type is int:
                action.type = fix_int_reraise_arg
            elif type(action) is argparse._StoreAction and action.type is None:
                # Prevents bugs like https://github.com/pwndbg/pwndbg/pull/3477
                print(message.error(f"Error parsing arguments for command: {parser.prog}"))
                print("You must set the argument type for a store action.")
                print(f"Erroneous action:\n\t{repr(action)}\n")
                assert False, "You must set the argument type for a store action."

        assert (
            parser.formatter_class is argparse.HelpFormatter
            and "All pwndbg commands should use the same formatter."
        )

        parser.formatter_class = CommandFormatter

        # Used by `pwndbg [filter]`
        assert (
            parser.description
            and parser.description.strip()
            and "A command must contain a description."
        )
        parser.description = parser.description.strip()

        # Run recursively on subparsers (if any)
        for action in parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                if level == 0:
                    top_level_name = parser.prog
                last_prog = "<doesn't exist>"
                for subparser in action.choices.values():
                    # Argparse creates duplicate objects for aliases, we don't need to
                    # reparse them (and shouldn't, as we will mess up the parser.prog).
                    if subparser.prog != last_prog:
                        CommandObj.initialize_parser_recursively(
                            subparser, top_level_name, level + 1
                        )

                    last_prog = subparser.prog

    def initialize_parser(self) -> None:
        # Set parser.prog so the help is generated properly.
        self.parser.prog = self.command_name

        # Clean up and check subcommands as well
        CommandObj.initialize_parser_recursively(self.parser, "", 0)

        # Add non-alias subcommands to self.subcommand_names which will
        # register them for tab-completion in the debugger.
        self.subcommand_names = None

        for action in self.parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                self.subcommand_names = []
                last_prog = "<doesn't exist>"
                for subcmd_name, subparser in action.choices.items():
                    if subparser.prog != last_prog:
                        self.subcommand_names.append(subcmd_name)
                    last_prog = subparser.prog
                # Not sure what multiple subparser actions would mean..
                break

        assert self.parser.description
        self.description = self.parser.description

        assert (
            not self.has_examples_string(self.description)
            and "Put examples into pwndbg.commands.Command(examples=your_example)."
        )
        assert (
            not self.has_notes_string(self.description)
            and "Put notes into pwndbg.commands.Command(notes=your_note)."
        )

        self.setup_epilog()

        # Generate command help (after stripping the parser's variables
        # and defining a formatter).
        self.help_str = self.parser.format_help()

    def invoke(self, argument: str, from_tty: bool) -> None:
        """Invoke the command with an argument string"""
        try:
            _ = pwndbg.dbg.selected_inferior()
        except pwndbg.dbg_mod.NoInferior:
            log.error("Pwndbg commands require a target binary to be selected")
            return

        # Put the arguments through the debugger
        try:
            arg_list = pwndbg.dbg.lex_args(argument)
        except (TypeError, pwndbg.dbg_mod.Error):
            pwndbg.exception.handle(self.function.__name__)
            return

        # Check OnlyWhenRunning before argparse so default arguments like
        # "$sp"/"$rip" don't blow up with cryptic resolution errors when
        # the program isn't running. Allow -h/--help through so users can
        # always read command help. See #1462.
        if "-h" not in arg_list and "--help" not in arg_list:
            allow_core = getattr(self.function, "_pwndbg_only_when_running_allow_core", None)
            if allow_core is not None and not (
                pwndbg.aglib.proc.alive()
                and not (not allow_core and pwndbg.aglib.proc.is_core_file())
            ):
                log.error(f"{func_name(self.function)}: The program is not being run.")
                return

        # Put the arguments through argparse
        try:
            kwargs = vars(self.parser.parse_args(arg_list))
        except SystemExit:
            # argparse complained about incorrect usage or printed
            # help and exited. Either way the appropriate message
            # is already printed and we shouldn't call the function.
            return

        try:
            self.repeat = self.check_repeated(argument, from_tty)
            # Call this object, same as `self(**kwargs)` but faster.
            self.__call__(**kwargs)
        finally:
            self.repeat = False

    def check_repeated(self, argument: str, from_tty: bool) -> bool:
        """
        Keep a record of all commands which come from the TTY.

        Returns:
            True if this command was executed by the user just hitting "enter".
        """
        # Don't care unless it's interactive use
        if not from_tty:
            return False

        last_line = pwndbg.dbg.history(1)

        # No history
        if not last_line:
            return False

        number, command = last_line[-1]
        # A new command was entered by the user
        if number not in CommandObj.history:
            CommandObj.history[number] = command
            return False

        # Somehow the command is different than we got before?
        if not command.endswith(argument):
            return False

        return True

    def __call__(self, *args: Any, **kwargs: Any) -> str | None:
        try:
            return self.function(*args, **kwargs)
        except TypeError:
            print(f"{self.command_name}: {self.description}")
            pwndbg.exception.handle(self.function.__name__)
        except ConnectionRefusedError:
            print(message.error("Connection Refused Exception."))
            print(message.hint("Did the decompiler integration connection die?"), end="")
            # If yes, we need to throw the connection out and fix up the manager's
            # state. The manager has not yet realized that the connection is doomed,
            # so we can check like this if we *were* connected.
            if pwndbg.dintegration.manager.is_connected():
                decompiler_name = pwndbg.dintegration.manager.decompiler_name()
                pwndbg.dintegration.manager.disconnect()
                print(message.hint(f" Automatically disabled {decompiler_name} integration."))
                print("Feel free to re-enable manually.")
            else:
                print()
        except TypeNotRecoveredError as e:
            print(message.error(f"recovering {e.name} failed with error:"))
            print(e)
            if "CONFIG_RANDSTRUCT" in pwndbg.aglib.kernel.kconfig():
                print(
                    message.warn(
                        "please note that some structs may not be recoverable when CONFIG_RANDSTRUCT=y"
                    )
                )

        except Exception:
            pwndbg.exception.handle(self.function.__name__)
        return None


class Command:
    """
    Parametrized decorator for functions that serve as pwndbg commands.

    Always use this to decorate your commands.
    """

    def __init__(
        self,
        parser_or_desc: argparse.ArgumentParser | str,
        *,  # All further parameters are not positional
        category: CommandCategory,
        command_name: str | None = None,
        aliases: list[str] = [],
        examples: str = "",
        notes: str = "",
        only_debuggers: set[pwndbg.dbg_mod.DebuggerType] | None = None,
        exclude_debuggers: set[pwndbg.dbg_mod.DebuggerType] | None = None,
    ) -> None:
        # Setup an ArgumentParser even if we were only passed a description.
        if isinstance(parser_or_desc, str):
            self.parser = argparse.ArgumentParser(description=parser_or_desc)
        else:
            assert isinstance(parser_or_desc, argparse.ArgumentParser)
            self.parser = parser_or_desc

        self.category = category
        self.command_name = command_name
        self.aliases = aliases
        self.examples = examples
        self.notes = notes
        self.only_debuggers = only_debuggers
        self.exclude_debuggers = exclude_debuggers

    def __call__(self, function: Callable[..., Any]) -> CommandObj:
        # Since this is the __call__ of a parametrized decorator, it is
        # invoked during decoration, and it must return a callable object
        # i.e. the "real" decorator of the function.

        # If this command is not valid for this debugger, do not even
        # pass it to ComandObj to be registered with the debugger API.
        # Also make sure it raises an error if it is called from the code.
        if self.only_debuggers is not None and pwndbg.dbg.name() not in self.only_debuggers:

            def decorator(*args: Any, **kwargs: Any) -> None:
                raise InvalidDebuggerError(
                    f"This command cannot be used in {pwndbg.dbg.name()}.\n"
                    f"It is only valid for {self.only_debuggers}."
                )

            return decorator  # type: ignore[return-value]
        if self.exclude_debuggers is not None and pwndbg.dbg.name() in self.exclude_debuggers:

            def decorator(*args: Any, **kwargs: Any) -> None:
                raise InvalidDebuggerError(
                    f"This command cannot be used in {pwndbg.dbg.name()}.\n"
                    f"It is invalid for {self.exclude_debuggers}."
                )

            return decorator  # type: ignore[return-value]

        # Since CommandObj has __call__ defined, an instance of it is a
        # callable object (which essentially decorates the function).
        return CommandObj(
            function,
            self.parser,
            self.command_name,
            self.category,
            self.aliases,
            self.examples,
            self.notes,
        )


def fix(
    arg: pwndbg.dbg_mod.Value | str, sloppy: bool = False, quiet: bool = True, reraise: bool = False
) -> str | pwndbg.dbg_mod.Value | None:
    """Fix a single command-line argument coming from the CLI.

    Arguments:
        arg: Original string representation (e.g. '0', '$rax', '$rax+44')
        sloppy: If ``arg`` cannot be evaluated, return ``arg``. (default: False)
        quiet: If an error occurs, suppress it. (default: True)
        reraise: If an error occurs, raise the exception. (default: False)

    Returns:
        Ideally a ``Value`` object.  May return a ``str`` if ``sloppy==True``.
        May return ``None`` if ``sloppy == False and reraise == False``.
    """
    if isinstance(arg, pwndbg.dbg_mod.Value):
        return arg

    frame = pwndbg.dbg.selected_frame()
    try:
        target: pwndbg.dbg_mod.Frame | pwndbg.dbg_mod.Process = (
            frame or pwndbg.dbg.selected_inferior()
        )
    except pwndbg.dbg_mod.NoInferior:
        raise AssertionError("Reached command expression evaluation with no frame or inferior")

    # Try to evaluate the expression in the local, or, failing that, global
    # context.
    try:
        return target.evaluate_expression(arg)
    except Exception:
        pass

    ex = None
    try:
        # This will fail if gdblib is not available. While the next check
        # alleviates the need for this call, it's not really equivalent, and
        # we'll need a debugger-agnostic version of regs.fix() if we want to
        # completely get rid of this call. We can't do that now because there's
        # no debugger-agnostic architecture functions. Those will come later.
        #
        # TODO: Port architecutre functions and `pwndbg.gdblib.regs.fix` to debugger-agnostic API and remove this.
        arg = pwndbg.aglib.regs.fix(arg)
        return target.evaluate_expression(arg)
    except Exception as e:
        ex = e

    # If that fails, try to treat the argument as the name of a register, and
    # see if that yields anything.
    if frame:
        regs = frame.regs()
        arg = arg.strip()
        arg = arg.removeprefix("$")
        reg = regs.by_name(arg)
        if reg:
            return reg

    # If both fail, check whether we want to print or re-raise the error we
    # might've gotten from `evaluate_expression`.
    if ex:
        if not quiet:
            print(ex)
        if reraise:
            raise ex

    if sloppy:
        return arg

    return None


def fix_reraise(*a: Any, **kw: Any) -> str | pwndbg.dbg_mod.Value | None:
    # Type error likely due to https://github.com/python/mypy/issues/6799
    return fix(*a, reraise=True, **kw)  # type: ignore[misc]


def fix_reraise_arg(arg: Any) -> pwndbg.dbg_mod.Value:
    """fix_reraise wrapper for evaluating command arguments"""
    try:
        # Will always return pwndbg.dbg_mod.Value because
        # sloppy=False (not str) and reraise=True (not None)
        fixed = fix(arg, sloppy=False, quiet=True, reraise=True)
        assert isinstance(fixed, pwndbg.dbg_mod.Value)
        return fixed
    except pwndbg.dbg_mod.Error as dbge:
        raise argparse.ArgumentTypeError(f"debugger couldn't resolve argument '{arg}': {dbge}")


def fix_int(*a: Any, **kw: Any) -> int:
    return int(fix(*a, **kw))


def fix_int_reraise(*a: Any, **kw: Any) -> int:
    return fix_int(*a, reraise=True, **kw)


def fix_int_reraise_arg(arg: Any) -> int:
    """fix_int_reraise wrapper for evaluating command arguments"""
    try:
        fixed: pwndbg.dbg_mod.Value = fix_reraise_arg(arg)
        if fixed.type.code == pwndbg.dbg_mod.TypeCode.FUNC:
            # Fixes issues with function ptrs (e.g. passing in `malloc`).
            func_addr = fixed.address
            if func_addr is None:
                raise argparse.ArgumentTypeError(
                    f"couldn't convert '{arg}' ({fixed.type.name_to_human_readable}) to int: Function is not addressable."
                )
            return int(func_addr)
        return int(fixed)
    except pwndbg.dbg_mod.Error as e:
        raise argparse.ArgumentTypeError(
            f"couldn't convert '{arg}' ({fixed.type.name_to_human_readable}) to int: {e}"
        )


def func_name(function: Callable[P, T]) -> str:
    return function.__name__.replace("_", "-")


def OnlyWhenLocal(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenLocal(*a: P.args, **kw: P.kwargs) -> T | None:
        if not pwndbg.aglib.remote.is_remote():
            return function(*a, **kw)

        msg = f'The "remote" target does not support "{function.__name__}".'

        if pwndbg.dbg.is_gdblib_available():
            msg += ' Try "help target" or "continue".'

        log.error(msg)
        return None

    return _OnlyWhenLocal


def OnlyWithFile(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWithFile(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.proc.exe():
            return function(*a, **kw)
        if pwndbg.aglib.qemu.is_qemu():
            log.error("Could not determine the target binary on QEMU.")
        else:
            log.error(f"{func_name(function)}: There is no file loaded.")
        return None

    return _OnlyWithFile


def OnlyWhenQemuKernel(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenQemuKernel(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        log.error(
            f"{func_name(function)}: This command may only be run when debugging the Linux kernel in QEMU."
        )
        return None

    return _OnlyWhenQemuKernel


def OnlyWhenUserspace(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenUserspace(*a: P.args, **kw: P.kwargs) -> T | None:
        if not pwndbg.aglib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        log.error(
            f"{func_name(function)}: This command may only be run when not debugging a QEMU kernel target."
        )
        return None

    return _OnlyWhenUserspace


def OnlyWithKernelDebugInfo(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWithKernelDebugInfo(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.kernel.has_debug_info():
            return function(*a, **kw)
        log.error(
            f"{func_name(function)}: This command may only be run when debugging a Linux kernel with debug info."
        )
        return None

    return _OnlyWithKernelDebugInfo


def OnlyWithKernelSymbols(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWithKernelSymbols(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.kernel.has_debug_symbols():
            return function(*a, **kw)
        log.error(
            f"{func_name(function)}: This command may only be run when debugging a Linux kernel with symbols.\n"
            + message.hint(
                "Check out vmlinux-to-elf to get them easily (https://github.com/marin-m/vmlinux-to-elf) or compile the kernel yourself."
            )
        )
        return None

    return _OnlyWithKernelSymbols


def OnlyWhenPagingEnabled(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenPagingEnabled(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.kernel.paging_enabled():
            return function(*a, **kw)
        log.error(f"{func_name(function)}: This command may only be run when paging is enabled.")
        return None

    return _OnlyWhenPagingEnabled


def WarnOnKernelConfigRandstruct(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _WarnOnKernelConfigRandstruct(*a: P.args, **kw: P.kwargs) -> T | None:
        if (
            not pwndbg.aglib.kernel.has_debug_info()
            and "CONFIG_RANDSTRUCT" in pwndbg.aglib.kernel.kconfig()
        ):
            log.warning("command output may be inaccurate because CONFIG_RANDSTRUCT=y")
        return function(*a, **kw)

    return _WarnOnKernelConfigRandstruct


def OnlyWhenRunning(
    func_when_no_kwargs: Callable[P, T] | None = None, *, allow_core: bool = True
) -> Callable[[Callable[P, T]], Callable[P, T]] | Callable[P, T]:
    # CommandObj.invoke reads this attribute before argparse so default
    # arguments like "$sp"/"$rip" don't blow up with cryptic resolution
    # errors when the program isn't running. See #1462.
    if func_when_no_kwargs is None:
        return functools.partial(OnlyWhenRunning, allow_core=allow_core)  # type: ignore[return-value]
    func_when_no_kwargs._pwndbg_only_when_running_allow_core = allow_core  # type: ignore[attr-defined]
    return func_when_no_kwargs


def OnlyWithTcache(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWithTcache(*a: P.args, **kw: P.kwargs) -> T | None:
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        if pwndbg.aglib.heap.current.has_tcache():
            return function(*a, **kw)
        log.error(
            f"{func_name(function)}: This version of GLIBC was not compiled with tcache support."
        )
        return None

    return _OnlyWithTcache


def OnlyWhenHeapIsInitialized(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWhenHeapIsInitialized(*a: P.args, **kw: P.kwargs) -> T | None:
        if pwndbg.aglib.heap.current is not None and pwndbg.aglib.heap.current.is_initialized():
            return function(*a, **kw)
        log.error(f"{func_name(function)}: Heap is not initialized yet.")
        return None

    return _OnlyWhenHeapIsInitialized


def _try2run_heap_command(function: Callable[P, T], *a: P.args, **kw: P.kwargs) -> T | None:
    e = log.error
    w = log.warning
    # Note: We will still raise the error for developers when exception-* is set to "on"
    try:
        return function(*a, **kw)
    except SymbolNotRecoveredError as err:
        e(f"{func_name(function)}: Fail to resolve the symbol: `{err.name}`")
        if "thread_arena" == err.name:
            w(
                "You are probably debugging a multi-threaded target without debug symbols, so we failed to determine which arena is used by the current thread.\n"
                "To resolve this issue, you can use the `arenas` command to list all arenas, and use `set thread-arena <addr>` to set the current thread's arena address you think is correct.\n"
            )
        else:
            w(
                f"You can try to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap-config` command output and set the config for `{err.name}`."
            )
        if pwndbg.config.exception_verbose or pwndbg.config.exception_debugger:
            raise err

        pwndbg.exception.inform_verbose_and_debug()
    except Exception as err:
        e(f"{func_name(function)}: An unknown error occurred when running this command.")
        if isinstance(pwndbg.aglib.heap.current, HeuristicHeap):
            w(
                "Maybe you can try to determine the libc symbols addresses manually, set them appropriately and re-run this command. For this, see the `heap-config` command output and set the `main_arena`, `mp_`, `global_max_fast`, `tcache` and `thread_arena` addresses."
            )
        else:
            w("You can try `set resolve-heap-via-heuristic force` and re-run this command.\n")
        if pwndbg.config.exception_verbose or pwndbg.config.exception_debugger:
            raise err

        pwndbg.exception.inform_verbose_and_debug()
    return None


def OnlyWithResolvedHeapSyms(function: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(function)
    def _OnlyWithResolvedHeapSyms(*a: P.args, **kw: P.kwargs) -> T | None:
        e = log.error
        w = log.warning

        # Operating under the assumption that the pwndbg/libc/ code can figure out
        # that we are using glibc with at least as good accuracy as the ptmalloc code.
        if pwndbg.libc.which() != pwndbg.libc.LibcType.GLIBC:
            e(f"The currently active libc isn't glibc. It's {pwndbg.libc.which().value}.")
            return None

        if (
            isinstance(pwndbg.aglib.heap.current, HeuristicHeap)
            and pwndbg.config.resolve_heap_via_heuristic == "auto"
            and DebugSymsHeap().can_be_resolved()
        ):
            # In auto mode, we will try to use the debug symbols if possible
            pwndbg.aglib.heap.current = DebugSymsHeap()

        if (
            pwndbg.aglib.heap.current is not None
            and isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
            and pwndbg.aglib.heap.current.can_be_resolved()
        ):
            return _try2run_heap_command(function, *a, **kw)

        static = not pwndbg.dbg.selected_inferior().is_dynamically_linked()
        if (
            isinstance(pwndbg.aglib.heap.current, DebugSymsHeap)
            and pwndbg.config.resolve_heap_via_heuristic == "auto"
        ):
            # In auto mode, if the debug symbols are not enough, we will try to use the heuristic if possible
            heuristic_heap = HeuristicHeap()
            if heuristic_heap.can_be_resolved():
                pwndbg.aglib.heap.current = heuristic_heap
                w(
                    "pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.\n"
                    "This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.\n"
                )
                return _try2run_heap_command(function, *a, **kw)
            if static:
                e(
                    "Can't find GLIBC version required for this command to work since this is a statically linked binary"
                )
                w(
                    "Please set the GLIBC version you think the target binary was compiled (using `set glibc <version>` command; e.g. 2.32) and re-run this command."
                )
            else:
                e(
                    "Can't find GLIBC version required for this command to work, maybe is because GLIBC is not loaded yet."
                )
                w(
                    "If you believe the GLIBC is loaded or this is a statically linked binary. "
                    "Please set the GLIBC version you think the target binary was compiled (using `set glibc <version>` command; e.g. 2.32) and re-run this command"
                )
        elif (
            isinstance(pwndbg.aglib.heap.current, DebugSymsHeap)
            and pwndbg.config.resolve_heap_via_heuristic == "force"
        ):
            e(
                "You are forcing to resolve the heap symbols via heuristic, but we cannot resolve the heap via the debug symbols."
            )
            w("Use `set resolve-heap-via-heuristic auto` and re-run this command.")
        else:
            # Note: Should not see this error, but just in case
            e("An unknown error occurred when resolved the heap.")
            pwndbg.exception.inform_report_issue("An unknown error occurred when resolved the heap")
        return None

    return _OnlyWithResolvedHeapSyms


def sloppy_gdb_parse(s: str) -> int | str:
    """
    This function should be used as ``argparse.ArgumentParser`` .add_argument method's `type` helper.

    This makes the type being parsed as gdb value and if that parsing fails,
    a string is returned.

    :param s: String.
    :return: Whatever gdb.parse_and_eval returns or string.
    """

    frame = pwndbg.dbg.selected_frame()
    try:
        target: pwndbg.dbg_mod.Frame | pwndbg.dbg_mod.Process = (
            frame or pwndbg.dbg.selected_inferior()
        )
    except pwndbg.dbg_mod.NoInferior:
        raise AssertionError("Reached command expression evaluation with no frame or inferior")

    try:
        val = pwndbg.aglib.symbol.lookup_symbol(s) or target.evaluate_expression(s)
        if val.type.code == pwndbg.dbg_mod.TypeCode.FUNC:
            return int(val.address)
        return int(val)
    except (TypeError, pwndbg.dbg_mod.Error):
        return s


def AddressExpr(s: str) -> int:
    """
    Parses an address expression. Returns an int.
    """
    val = sloppy_gdb_parse(s)

    if not isinstance(val, int):
        raise argparse.ArgumentTypeError(f"Incorrect address (or GDB expression): {s}")

    return val


def HexOrAddressExpr(s: str) -> int:
    """
    Parses string as hexadecimal int or an address expression. Returns an int.
    (e.g. '1234' will return 0x1234)
    """
    try:
        return int(s, 16)
    except ValueError:
        return AddressExpr(s)


def load_commands() -> None:
    # pylint: disable=import-outside-toplevel
    import pwndbg.dbg_mod

    if pwndbg.dbg.is_gdblib_available():
        import pwndbg.commands.ai
        import pwndbg.commands.attachp
        import pwndbg.commands.branch
        import pwndbg.commands.cymbol
        import pwndbg.commands.got_tracking
        import pwndbg.commands.ignore
        import pwndbg.commands.ipython_interactive
        import pwndbg.commands.killthreads
        import pwndbg.commands.peda
        import pwndbg.commands.ptmalloc2_tracking
        import pwndbg.commands.reload
        import pwndbg.commands.ropper
        import pwndbg.commands.segments
        import pwndbg.commands.updown

    import pwndbg.commands.argv
    import pwndbg.commands.aslr
    import pwndbg.commands.asm
    import pwndbg.commands.auxv
    import pwndbg.commands.binder
    import pwndbg.commands.buddydump
    import pwndbg.commands.canary
    import pwndbg.commands.checksec
    import pwndbg.commands.comments
    import pwndbg.commands.commpage
    import pwndbg.commands.config
    import pwndbg.commands.context
    import pwndbg.commands.cpsr
    import pwndbg.commands.cyclic
    import pwndbg.commands.decompiler_integration
    import pwndbg.commands.dev
    import pwndbg.commands.distance
    import pwndbg.commands.dt
    import pwndbg.commands.dumpargs
    import pwndbg.commands.elf
    import pwndbg.commands.errno
    import pwndbg.commands.exithandlers
    import pwndbg.commands.flags
    import pwndbg.commands.gdt
    import pwndbg.commands.godbg
    import pwndbg.commands.got
    import pwndbg.commands.hex2ptr
    import pwndbg.commands.hexdump
    import pwndbg.commands.hijack_fd
    import pwndbg.commands.jemalloc
    import pwndbg.commands.kbase
    import pwndbg.commands.kbpf
    import pwndbg.commands.kchecksec
    import pwndbg.commands.kcmdline
    import pwndbg.commands.kconfig
    import pwndbg.commands.kcurrent
    import pwndbg.commands.kdmabuf
    import pwndbg.commands.kdmesg
    import pwndbg.commands.klookup
    import pwndbg.commands.kmem_trace
    import pwndbg.commands.kmod
    import pwndbg.commands.knft
    import pwndbg.commands.ksyscalls
    import pwndbg.commands.ktask
    import pwndbg.commands.kversion
    import pwndbg.commands.leakfind
    import pwndbg.commands.libcinfo
    import pwndbg.commands.linkmap
    import pwndbg.commands.mallocng
    import pwndbg.commands.memoize
    import pwndbg.commands.mmap
    import pwndbg.commands.mprotect
    import pwndbg.commands.msr
    import pwndbg.commands.nearpc
    import pwndbg.commands.next
    import pwndbg.commands.onegadget
    import pwndbg.commands.p2p
    import pwndbg.commands.paging
    import pwndbg.commands.parse_seccomp
    import pwndbg.commands.patch
    import pwndbg.commands.pie
    import pwndbg.commands.plist
    import pwndbg.commands.probeleak
    import pwndbg.commands.procinfo
    import pwndbg.commands.profiler
    import pwndbg.commands.ptmalloc2
    import pwndbg.commands.pwndbg_
    import pwndbg.commands.radare2
    import pwndbg.commands.retaddr
    import pwndbg.commands.rizin
    import pwndbg.commands.rop
    import pwndbg.commands.saved_register_frames
    import pwndbg.commands.search
    import pwndbg.commands.sigreturn
    import pwndbg.commands.slab
    import pwndbg.commands.spray
    import pwndbg.commands.start
    import pwndbg.commands.strings
    import pwndbg.commands.telescope
    import pwndbg.commands.tips
    import pwndbg.commands.tls
    import pwndbg.commands.valist
    import pwndbg.commands.version
    import pwndbg.commands.vmmap
    import pwndbg.commands.windbg
    import pwndbg.commands.xinfo
    import pwndbg.commands.xor
