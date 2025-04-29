from __future__ import annotations

import argparse
import functools
import inspect
import io
import logging
from enum import Enum
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Literal
from typing import Optional
from typing import Set
from typing import Tuple
from typing import TypeVar

from typing_extensions import ParamSpec
from typing_extensions import override

import pwndbg.aglib.heap
import pwndbg.aglib.kernel
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.regs
import pwndbg.exception
from pwndbg.aglib.heap.ptmalloc import DebugSymsHeap
from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator
from pwndbg.aglib.heap.ptmalloc import HeuristicHeap
from pwndbg.aglib.heap.ptmalloc import SymbolUnresolvableError

log = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")

commands: List[CommandObj] = []
command_names: Set[str] = set()


class CommandCategory(str, Enum):
    START = "Start"
    NEXT = "Step/Next/Continue"
    CONTEXT = "Context"
    PTMALLOC2 = "GLibc ptmalloc2 Heap"
    JEMALLOC = "jemalloc Heap"
    BREAKPOINT = "Breakpoint"
    MEMORY = "Memory"
    STACK = "Stack"
    REGISTER = "Register"
    PROCESS = "Process"
    LINUX = "Linux/libc/ELF"
    DISASS = "Disassemble"
    MISC = "Misc"
    KERNEL = "Kernel"
    INTEGRATIONS = "Integrations"
    WINDBG = "WinDbg"
    PWNDBG = "pwndbg"
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

    pass


class CommandFormatter(argparse.RawDescriptionHelpFormatter):
    """
    The formatter_class that is passed to argparse for all
    commands.

    Subclassing this isn't officially supported, but there
    isn't a good alternative.
    """

    @override
    def _get_help_string(self, action):
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

    builtin_override_whitelist: Set[str] = {
        "up",
        "down",
        "search",
        "pwd",
        "start",
        "starti",
        "ignore",
    }
    history: Dict[int, str] = {}

    def __init__(
        self,
        function: Callable[..., str | None],
        parser: argparse.ArgumentParser,
        command_name: str | None,
        category: CommandCategory,
        aliases: List[str],
        /,  # All parameters must be passed in positionally
    ) -> None:
        assert function
        self.function = function

        self.command_name = command_name
        if self.command_name is None:
            # Take the command name from the name of the function
            # which defines it, but replace '_' with '-'.
            self.command_name = function.__name__.replace("_", "-")

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
        self.category = category

        self.aliases = aliases

        assert parser
        self.parser = parser
        # Sets self.help_str and self.description (among other stuff).
        self.initialize_parser()

        # Let the debugger and pwndbg global state know about it.
        self.register_command()

        # For commands like hexdump where you get new output from
        # continuous invocations.
        self.repeat = False

    def register_command(self):
        """
        Register this object command with the underlying debugger
        and update pwndbg global state to know about this command.
        """

        def _handler(_debugger, arguments, is_interactive):
            self.invoke(arguments, is_interactive)

        # Keep a handle to the command and its aliases so we can
        # easily remove them if necessary (not supported with GDB).
        self.handles = []

        # Tell the debugger about the command...
        self.handles.append(pwndbg.dbg.add_command(self.command_name, _handler, self.help_str))
        # ...and all of its aliases.
        for alias in self.aliases:
            self.handles.append(pwndbg.dbg.add_command(alias, _handler, self.help_str))

        command_names.add(self.command_name)
        commands.append(self)

    def initialize_parser(self):
        # Set parser.prog so the help is generated properly.
        self.parser.prog = self.command_name

        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        # FIXME: this is weird
        for action in self.parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                action.type = str
            if action.dest == "help":
                continue
            if action.type is int:
                action.type = fix_int_reraise_arg
            elif action.type is None:
                action.type = fix_reraise_arg

        assert (
            self.parser.formatter_class is argparse.HelpFormatter
            and "All pwndbg commands should use the same formatter."
        )

        self.parser.formatter_class = CommandFormatter

        # Used by `pwndbg [filter]`
        assert (
            self.parser.description
            and self.parser.description.strip()
            and "A command must contain a description."
        )
        self.description = self.parser.description = self.parser.description.strip()
        if self.parser.epilog:
            self.epilog = self.parser.epilog = self.parser.epilog.strip()

        # Generate command help (after stripping the parser's variables
        # and defining a formatter).
        self.help_str = self.parser.format_help()

    def invoke(self, argument: str, from_tty: bool) -> None:
        """Invoke the command with an argument string"""
        if not pwndbg.dbg.selected_inferior():
            log.error("Pwndbg commands require a target binary to be selected")
            return

        # Put the arguments through the debugger
        try:
            arg_list = pwndbg.dbg.lex_args(argument)
        except (TypeError, pwndbg.dbg_mod.Error):
            pwndbg.exception.handle(self.function.__name__)
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
        aliases: List[str] = [],
        only_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
        exclude_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
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

            def decorator(*args, **kwargs):
                raise InvalidDebuggerError(
                    f"This command cannot be used in {pwndbg.dbg.name()}.\n"
                    f"It is only valid for {self.only_debuggers}."
                )

            return decorator  # type: ignore[return-value]
        if self.exclude_debuggers is not None and pwndbg.dbg.name() in self.exclude_debuggers:

            def decorator(*args, **kwargs):
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
    target: pwndbg.dbg_mod.Frame | pwndbg.dbg_mod.Process = (
        frame if frame else pwndbg.dbg.selected_inferior()
    )
    assert target, "Reached command expression evaluation with no frame or inferior"

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
        if arg.startswith("$"):
            arg = arg[1:]
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


def fix_reraise(*a, **kw) -> str | pwndbg.dbg_mod.Value | None:
    # Type error likely due to https://github.com/python/mypy/issues/6799
    return fix(*a, reraise=True, **kw)  # type: ignore[misc]


def fix_reraise_arg(arg) -> pwndbg.dbg_mod.Value:
    """fix_reraise wrapper for evaluating command arguments"""
    try:
        # Will always return pwndbg.dbg_mod.Value because
        # sloppy=False (not str) and reraise=True (not None)
        fixed = fix(arg, sloppy=False, quiet=True, reraise=True)
        assert isinstance(fixed, pwndbg.dbg_mod.Value)
        return fixed
    except pwndbg.dbg_mod.Error as dbge:
        raise argparse.ArgumentTypeError(f"debugger couldn't resolve argument '{arg}': {dbge}")


def fix_int(*a, **kw) -> int:
    return int(fix(*a, **kw))


def fix_int_reraise(*a, **kw) -> int:
    return fix_int(*a, reraise=True, **kw)


def fix_int_reraise_arg(arg) -> int:
    """fix_int_reraise wrapper for evaluating command arguments"""
    try:
        fixed = fix_reraise_arg(arg)
        return int(fixed)
    except pwndbg.dbg_mod.Error as e:
        raise argparse.ArgumentTypeError(
            f"couldn't convert '{arg}' ({fixed.type.name_to_human_readable}) to int: {e}"
        )


def func_name(function: Callable[P, T]) -> str:
    return function.__name__.replace("_", "-")


def OnlyWhenLocal(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenLocal(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if not pwndbg.aglib.remote.is_remote():
            return function(*a, **kw)

        msg = f'The "remote" target does not support "{function.__name__}".'

        if pwndbg.dbg.is_gdblib_available():
            msg += ' Try "help target" or "continue".'

        log.error(msg)
        return None

    return _OnlyWhenLocal


def OnlyWithFile(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithFile(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.aglib.proc.exe:
            return function(*a, **kw)
        else:
            if pwndbg.aglib.qemu.is_qemu():
                log.error("Could not determine the target binary on QEMU.")
            else:
                log.error(f"{func_name(function)}: There is no file loaded.")
            return None

    return _OnlyWithFile


def OnlyWhenQemuKernel(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenQemuKernel(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.aglib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        else:
            log.error(
                f"{func_name(function)}: This command may only be run when debugging the Linux kernel in QEMU."
            )
            return None

    return _OnlyWhenQemuKernel


def OnlyWhenUserspace(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenUserspace(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if not pwndbg.aglib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        else:
            log.error(
                f"{func_name(function)}: This command may only be run when not debugging a QEMU kernel target."
            )
            return None

    return _OnlyWhenUserspace


def OnlyWithKernelDebugSyms(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithKernelDebugSyms(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.aglib.kernel.has_debug_syms():
            return function(*a, **kw)
        else:
            log.error(
                f"{func_name(function)}: This command may only be run when debugging a Linux kernel with debug symbols."
            )
            return None

    return _OnlyWithKernelDebugSyms


def OnlyWhenPagingEnabled(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenPagingEnabled(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.aglib.kernel.paging_enabled():
            return function(*a, **kw)
        else:
            log.error(
                f"{func_name(function)}: This command may only be run when paging is enabled."
            )
            return None

    return _OnlyWhenPagingEnabled


def OnlyWhenRunning(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenRunning(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        # TODO: Properly support OnlyWhenRunning without `gdblib`.
        if pwndbg.aglib.proc.alive:
            return function(*a, **kw)
        else:
            log.error(f"{func_name(function)}: The program is not being run.")
            return None

    return _OnlyWhenRunning


def OnlyWithTcache(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithTcache(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        if pwndbg.aglib.heap.current.has_tcache():
            return function(*a, **kw)
        else:
            log.error(
                f"{func_name(function)}: This version of GLIBC was not compiled with tcache support."
            )
            return None

    return _OnlyWithTcache


def OnlyWhenHeapIsInitialized(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenHeapIsInitialized(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.aglib.heap.current is not None and pwndbg.aglib.heap.current.is_initialized():
            return function(*a, **kw)
        else:
            log.error(f"{func_name(function)}: Heap is not initialized yet.")
            return None

    return _OnlyWhenHeapIsInitialized


def _try2run_heap_command(function: Callable[P, T], *a: P.args, **kw: P.kwargs) -> T | None:
    e = log.error
    w = log.warning
    # Note: We will still raise the error for developers when exception-* is set to "on"
    try:
        return function(*a, **kw)
    except SymbolUnresolvableError as err:
        e(f"{func_name(function)}: Fail to resolve the symbol: `{err.symbol}`")
        if "thread_arena" == err.symbol:
            w(
                "You are probably debugging a multi-threaded target without debug symbols, so we failed to determine which arena is used by the current thread.\n"
                "To resolve this issue, you can use the `arenas` command to list all arenas, and use `set thread-arena <addr>` to set the current thread's arena address you think is correct.\n"
            )
        else:
            w(
                f"You can try to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap-config` command output and set the config for `{err.symbol}`."
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
        else:
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
                elif static:
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
            elif pwndbg.glibc.get_version() is None:
                if static:
                    e("Can't resolve the heap since the GLIBC version is not set.")
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
            else:
                # Note: Should not see this error, but just in case
                e("An unknown error occurred when resolved the heap.")
                pwndbg.exception.inform_report_issue(
                    "An unknown error occurred when resolved the heap"
                )
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
    target: pwndbg.dbg_mod.Frame | pwndbg.dbg_mod.Process = (
        frame if frame else pwndbg.dbg.selected_inferior()
    )
    assert target, "Reached command expression evaluation with no frame or inferior"

    try:
        val = target.evaluate_expression(s)
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
    import pwndbg.dbg

    if pwndbg.dbg.is_gdblib_available():
        import pwndbg.commands.ai
        import pwndbg.commands.attachp
        import pwndbg.commands.binja_functions
        import pwndbg.commands.branch
        import pwndbg.commands.cymbol
        import pwndbg.commands.got
        import pwndbg.commands.got_tracking
        import pwndbg.commands.ptmalloc2_tracking
        import pwndbg.commands.ida
        import pwndbg.commands.ignore
        import pwndbg.commands.ipython_interactive
        import pwndbg.commands.killthreads
        import pwndbg.commands.peda
        import pwndbg.commands.reload
        import pwndbg.commands.ropper
        import pwndbg.commands.segments

    import pwndbg.commands.argv
    import pwndbg.commands.aslr
    import pwndbg.commands.asm
    import pwndbg.commands.auxv
    import pwndbg.commands.binder
    import pwndbg.commands.binja
    import pwndbg.commands.canary
    import pwndbg.commands.checksec
    import pwndbg.commands.comments
    import pwndbg.commands.config
    import pwndbg.commands.context
    import pwndbg.commands.cpsr
    import pwndbg.commands.cyclic
    import pwndbg.commands.dev
    import pwndbg.commands.distance
    import pwndbg.commands.dt
    import pwndbg.commands.dumpargs
    import pwndbg.commands.elf
    import pwndbg.commands.flags
    import pwndbg.commands.gdt
    import pwndbg.commands.ghidra
    import pwndbg.commands.godbg
    import pwndbg.commands.hex2ptr
    import pwndbg.commands.hexdump
    import pwndbg.commands.hijack_fd
    import pwndbg.commands.integration
    import pwndbg.commands.jemalloc
    import pwndbg.commands.kbase
    import pwndbg.commands.kchecksec
    import pwndbg.commands.kcmdline
    import pwndbg.commands.kconfig
    import pwndbg.commands.klookup
    import pwndbg.commands.knft
    import pwndbg.commands.kversion
    import pwndbg.commands.leakfind
    import pwndbg.commands.libcinfo
    import pwndbg.commands.linkmap
    import pwndbg.commands.memoize
    import pwndbg.commands.misc
    import pwndbg.commands.mmap
    import pwndbg.commands.mprotect
    import pwndbg.commands.nearpc
    import pwndbg.commands.next
    import pwndbg.commands.onegadget
    import pwndbg.commands.p2p
    import pwndbg.commands.patch
    import pwndbg.commands.pcplist
    import pwndbg.commands.pie
    import pwndbg.commands.plist
    import pwndbg.commands.probeleak
    import pwndbg.commands.procinfo
    import pwndbg.commands.profiler
    import pwndbg.commands.ptmalloc2
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
