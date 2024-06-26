from __future__ import annotations

import argparse
import functools
import io
import logging
from enum import Enum
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple
from typing import TypeVar

from typing_extensions import ParamSpec

import pwndbg.exception

# These aren't available under LLDB, and we can't get rid of them until all of
# this functionality has been ported to the Debugger API.
#
# TODO: Replace these with uses of the Debugger API.
if pwndbg.dbg.is_gdblib_available():
    import pwndbg.gdblib.heap
    import pwndbg.gdblib.kernel
    import pwndbg.gdblib.proc
    import pwndbg.gdblib.qemu
    import pwndbg.gdblib.regs
    from pwndbg.gdblib.heap.ptmalloc import DebugSymsHeap
    from pwndbg.gdblib.heap.ptmalloc import GlibcMemoryAllocator
    from pwndbg.gdblib.heap.ptmalloc import HeuristicHeap
    from pwndbg.gdblib.heap.ptmalloc import SymbolUnresolvableError

log = logging.getLogger(__name__)

T = TypeVar("T")
P = ParamSpec("P")

commands: List[Command] = []
command_names: Set[str] = set()


class CommandCategory(str, Enum):
    START = "Start"
    NEXT = "Step/Next/Continue"
    CONTEXT = "Context"
    HEAP = "Heap"
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


class Command:
    """Generic command wrapper"""

    builtin_override_whitelist: Set[str] = {"up", "down", "search", "pwd", "start", "ignore"}
    history: Dict[int, str] = {}

    def __init__(
        self,
        function: Callable[..., str | None],
        prefix: bool = False,
        command_name: str | None = None,
        shell: bool = False,
        is_alias: bool = False,
        aliases: List[str] = [],
        category: CommandCategory = CommandCategory.MISC,
    ) -> None:
        self.is_alias = is_alias
        self.aliases = aliases
        self.category = category
        self.shell = shell

        if command_name is None:
            command_name = function.__name__

        def _handler(_debugger, arguments, is_interactive):
            self.invoke(arguments, is_interactive)

        self.handle = pwndbg.dbg.add_command(command_name, _handler)
        self.function = function

        if command_name in command_names:
            raise Exception(f"Cannot add command {command_name}: already exists.")
        if (
            command_name in GDB_BUILTIN_COMMANDS
            and command_name not in self.builtin_override_whitelist
            and not pwndbg_is_reloading
        ):
            raise Exception(f'Cannot override non-whitelisted built-in command "{command_name}"')

        command_names.add(command_name)
        commands.append(self)

        functools.update_wrapper(self, function)
        self.__name__ = command_name

        self.repeat = False

    def split_args(self, argument: str) -> Tuple[List[str], Dict[Any, Any]]:
        """Split a command-line string from the user into arguments.

        Returns:
            A ``(tuple, dict)``, in the form of ``*args, **kwargs``.
            The contents of the tuple/dict are undefined.
        """
        return pwndbg.dbg.lex_args(argument), {}

    def invoke(self, argument: str, from_tty: bool) -> None:
        """Invoke the command with an argument string"""
        try:
            args, kwargs = self.split_args(argument)
        except SystemExit:
            # Raised when the usage is printed by an ArgparsedCommand
            return
        except (TypeError, pwndbg.dbg_mod.Error):
            pwndbg.exception.handle(self.function.__name__)
            return

        if not pwndbg.dbg.selected_inferior():
            log.error("Pwndbg commands require a target binary to be selected")
            return

        try:
            self.repeat = self.check_repeated(argument, from_tty)
            self(*args, **kwargs)
        finally:
            self.repeat = False

    def check_repeated(self, argument: str, from_tty: bool) -> bool:
        """Keep a record of all commands which come from the TTY.

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
        if number not in Command.history:
            Command.history[number] = command
            return False

        # Somehow the command is different than we got before?
        if not command.endswith(argument):
            return False

        return True

    def __call__(self, *args: Any, **kwargs: Any) -> str | None:
        try:
            return self.function(*args, **kwargs)
        except TypeError:
            print(f"{self.function.__name__.strip()!r}: {self.function.__doc__.strip()}")
            pwndbg.exception.handle(self.function.__name__)
        except Exception:
            pwndbg.exception.handle(self.function.__name__)
        return None


def fix(
    arg: pwndbg.dbg_mod.Value | str, sloppy: bool = False, quiet: bool = True, reraise: bool = False
) -> str | pwndbg.dbg_mod.Value | None:
    """Fix a single command-line argument coming from the CLI.

    Arguments:
        arg(str): Original string representation (e.g. '0', '$rax', '$rax+44')
        sloppy(bool): If ``arg`` cannot be evaluated, return ``arg``. (default: False)
        quiet(bool): If an error occurs, suppress it. (default: True)
        reraise(bool): If an error occurs, raise the exception. (default: False)

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
        arg = pwndbg.gdblib.regs.fix(arg)
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


def fix_int(*a, **kw) -> int:
    return int(fix(*a, **kw))


def fix_int_reraise(*a, **kw) -> int:
    return fix_int(*a, reraise=True, **kw)


def OnlyWithFile(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithFile(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.proc.exe:
            return function(*a, **kw)
        else:
            if pwndbg.gdblib.qemu.is_qemu():
                log.error("Could not determine the target binary on QEMU.")
            else:
                log.error(f"{function.__name__}: There is no file loaded.")
            return None

    return _OnlyWithFile


def OnlyWhenQemuKernel(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenQemuKernel(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        else:
            log.error(
                f"{function.__name__}: This command may only be run when debugging the Linux kernel in QEMU."
            )
            return None

    return _OnlyWhenQemuKernel


def OnlyWhenUserspace(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenUserspace(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if not pwndbg.gdblib.qemu.is_qemu_kernel():
            return function(*a, **kw)
        else:
            log.error(
                f"{function.__name__}: This command may only be run when not debugging a QEMU kernel target."
            )
            return None

    return _OnlyWhenUserspace


def OnlyWithArch(arch_names: List[str]) -> Callable[[Callable[P, T]], Callable[P, Optional[T]]]:
    """Decorates function to work only with the specified archictectures."""
    for arch in arch_names:
        if arch not in pwndbg.gdblib.arch_mod.ARCHS:
            raise ValueError(
                f"OnlyWithArch used with unsupported arch={arch}. Must be one of {', '.join(arch_names)}"
            )

    def decorator(function: Callable[P, T]) -> Callable[P, Optional[T]]:
        @functools.wraps(function)
        def _OnlyWithArch(*a: P.args, **kw: P.kwargs) -> Optional[T]:
            if pwndbg.gdblib.arch.name in arch_names:
                return function(*a, **kw)
            else:
                arches_str = ", ".join(arch_names)
                log.error(
                    f"{function.__name__}: This command may only be run on the {arches_str} architecture(s)"
                )
                return None

        return _OnlyWithArch

    return decorator


def OnlyWithKernelDebugSyms(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithKernelDebugSyms(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.kernel.has_debug_syms():
            return function(*a, **kw)
        else:
            log.error(
                f"{function.__name__}: This command may only be run when debugging a Linux kernel with debug symbols."
            )
            return None

    return _OnlyWithKernelDebugSyms


def OnlyWhenPagingEnabled(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenPagingEnabled(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.kernel.paging_enabled():
            return function(*a, **kw)
        else:
            log.error(f"{function.__name__}: This command may only be run when paging is enabled.")
            return None

    return _OnlyWhenPagingEnabled


def OnlyWhenRunning(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenRunning(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.proc.alive:
            return function(*a, **kw)
        else:
            log.error(f"{function.__name__}: The program is not being run.")
            return None

    return _OnlyWhenRunning


def OnlyWithTcache(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWithTcache(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        assert isinstance(pwndbg.gdblib.heap.current, GlibcMemoryAllocator)
        if pwndbg.gdblib.heap.current.has_tcache():
            return function(*a, **kw)
        else:
            log.error(
                f"{function.__name__}: This version of GLIBC was not compiled with tcache support."
            )
            return None

    return _OnlyWithTcache


def OnlyWhenHeapIsInitialized(function: Callable[P, T]) -> Callable[P, Optional[T]]:
    @functools.wraps(function)
    def _OnlyWhenHeapIsInitialized(*a: P.args, **kw: P.kwargs) -> Optional[T]:
        if pwndbg.gdblib.heap.current is not None and pwndbg.gdblib.heap.current.is_initialized():
            return function(*a, **kw)
        else:
            log.error(f"{function.__name__}: Heap is not initialized yet.")
            return None

    return _OnlyWhenHeapIsInitialized


# TODO/FIXME: Move this elsewhere? Have better logic for that? Maybe caching?
def _is_statically_linked() -> bool:
    out = gdb.execute("info dll", to_string=True)
    return "No shared libraries loaded at this time." in out


def _try2run_heap_command(function: Callable[P, T], *a: P.args, **kw: P.kwargs) -> T | None:
    e = log.error
    w = log.warning
    # Note: We will still raise the error for developers when exception-* is set to "on"
    try:
        return function(*a, **kw)
    except SymbolUnresolvableError as err:
        e(f"{function.__name__}: Fail to resolve the symbol: `{err.symbol}`")
        if "thread_arena" == err.symbol:
            w(
                "You are probably debugging a multi-threaded target without debug symbols, so we failed to determine which arena is used by the current thread.\n"
                "To resolve this issue, you can use the `arenas` command to list all arenas, and use `set thread-arena <addr>` to set the current thread's arena address you think is correct.\n"
            )
        else:
            w(
                f"You can try to determine the libc symbols addresses manually and set them appropriately. For this, see the `heap_config` command output and set the config for `{err.symbol}`."
            )
        if pwndbg.config.exception_verbose or pwndbg.config.exception_debugger:
            raise err

        pwndbg.exception.inform_verbose_and_debug()
    except Exception as err:
        e(f"{function.__name__}: An unknown error occurred when running this command.")
        if isinstance(pwndbg.gdblib.heap.current, HeuristicHeap):
            w(
                "Maybe you can try to determine the libc symbols addresses manually, set them appropriately and re-run this command. For this, see the `heap_config` command output and set the `main_arena`, `mp_`, `global_max_fast`, `tcache` and `thread_arena` addresses."
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
        w = log.warn
        if (
            isinstance(pwndbg.gdblib.heap.current, HeuristicHeap)
            and pwndbg.config.resolve_heap_via_heuristic == "auto"
            and DebugSymsHeap().can_be_resolved()
        ):
            # In auto mode, we will try to use the debug symbols if possible
            pwndbg.gdblib.heap.current = DebugSymsHeap()
        if (
            pwndbg.gdblib.heap.current is not None
            and isinstance(pwndbg.gdblib.heap.current, GlibcMemoryAllocator)
            and pwndbg.gdblib.heap.current.can_be_resolved()
        ):
            return _try2run_heap_command(function, *a, **kw)
        else:
            if (
                isinstance(pwndbg.gdblib.heap.current, DebugSymsHeap)
                and pwndbg.config.resolve_heap_via_heuristic == "auto"
            ):
                # In auto mode, if the debug symbols are not enough, we will try to use the heuristic if possible
                heuristic_heap = HeuristicHeap()
                if heuristic_heap.can_be_resolved():
                    pwndbg.gdblib.heap.current = heuristic_heap
                    w(
                        "pwndbg will try to resolve the heap symbols via heuristic now since we cannot resolve the heap via the debug symbols.\n"
                        "This might not work in all cases. Use `help set resolve-heap-via-heuristic` for more details.\n"
                    )
                    return _try2run_heap_command(function, *a, **kw)
                elif _is_statically_linked():
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
                isinstance(pwndbg.gdblib.heap.current, DebugSymsHeap)
                and pwndbg.config.resolve_heap_via_heuristic == "force"
            ):
                e(
                    "You are forcing to resolve the heap symbols via heuristic, but we cannot resolve the heap via the debug symbols."
                )
                w("Use `set resolve-heap-via-heuristic auto` and re-run this command.")
            elif pwndbg.glibc.get_version() is None:
                if _is_statically_linked():
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


class _ArgparsedCommand(Command):
    def __init__(
        self,
        parser: argparse.ArgumentParser,
        function,
        command_name=None,
        *a,
        **kw,
    ) -> None:
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

        # Type error likely due to https://github.com/python/mypy/issues/6799
        super().__init__(  # type: ignore[misc]
            function,
            command_name=command_name,
            *a,
            **kw,
        )

    def split_args(self, argument: str):
        argv = pwndbg.dbg.lex_args(argument)
        return (), vars(self.parser.parse_args(argv))


class ArgparsedCommand:
    """Adds documentation and offloads parsing for a Command via argparse"""

    def __init__(
        self,
        parser_or_desc: argparse.ArgumentParser | str,
        aliases: List[str] = [],
        command_name: str | None = None,
        category: CommandCategory = CommandCategory.MISC,
    ) -> None:
        """
        :param parser_or_desc: `argparse.ArgumentParser` instance or `str`
        """
        if isinstance(parser_or_desc, str):
            self.parser = argparse.ArgumentParser(description=parser_or_desc)
        else:
            self.parser = parser_or_desc
        self.aliases = aliases
        self._command_name = command_name
        self.category = category
        # We want to run all integer and otherwise-unspecified arguments
        # through fix() so that GDB parses it.
        for action in self.parser._actions:
            if isinstance(action, argparse._SubParsersAction):
                action.type = str
            if action.dest == "help":
                continue
            if action.type == int:
                action.type = fix_int_reraise
            if action.type is None:
                action.type = fix_reraise
            if action.default is not None:
                action.help += " (default: %(default)s)"

    def __call__(self, function: Callable[..., Any]) -> _ArgparsedCommand:
        for alias in self.aliases:
            _ArgparsedCommand(
                self.parser, function, command_name=alias, is_alias=True, category=self.category
            )
        return _ArgparsedCommand(
            self.parser,
            function,
            command_name=self._command_name,
            aliases=self.aliases,
            category=self.category,
        )


# These values are only used by `sloppy_gdb_parse`, and it, in turn, only seems
# to end up being used by `pwndbg.commands.windbg`, through `AddressExpr` and
# `HexOrAddressExpr`. By gating both these values and the `windbg` command family
# behind `is_gdblib_available`, we get around that.
#
# TODO: Remove this after the `windbg` command family has been ported to the Debugger API.
if pwndbg.dbg.is_gdblib_available():
    import gdb

    # We use a 64-bit max value literal here instead of pwndbg.gdblib.arch.current
    # as realistically its ok to pull off the biggest possible type here
    # We cache its GDB value type which is 'unsigned long long'
    _mask = 0xFFFFFFFFFFFFFFFF
    _mask_val_type = gdb.Value(_mask).type


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
        # We can't just return int(val) because GDB may return:
        # "Python Exception <class 'gdb.error'> Cannot convert value to long."
        # e.g. for:
        # pwndbg> pi int(gdb.parse_and_eval('__libc_start_main'))
        #
        # Here, the _mask_val.type should be `unsigned long long`
        return int(val.cast(_mask_val_type))
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
        import pwndbg.commands.argv
        import pwndbg.commands.aslr
        import pwndbg.commands.asm
        import pwndbg.commands.attachp
        import pwndbg.commands.auxv
        import pwndbg.commands.binder
        import pwndbg.commands.binja
        import pwndbg.commands.branch
        import pwndbg.commands.canary
        import pwndbg.commands.checksec
        import pwndbg.commands.comments
        import pwndbg.commands.config
        import pwndbg.commands.context
        import pwndbg.commands.cpsr
        import pwndbg.commands.cyclic
        import pwndbg.commands.cymbol
        import pwndbg.commands.dev
        import pwndbg.commands.distance
        import pwndbg.commands.dt
        import pwndbg.commands.dumpargs
        import pwndbg.commands.elf
        import pwndbg.commands.flags
        import pwndbg.commands.ghidra
        import pwndbg.commands.got
        import pwndbg.commands.got_tracking
        import pwndbg.commands.heap
        import pwndbg.commands.heap_tracking
        import pwndbg.commands.hexdump
        import pwndbg.commands.ida
        import pwndbg.commands.ignore
        import pwndbg.commands.ipython_interactive
        import pwndbg.commands.kbase
        import pwndbg.commands.kchecksec
        import pwndbg.commands.kcmdline
        import pwndbg.commands.kconfig
        import pwndbg.commands.killthreads
        import pwndbg.commands.kversion
        import pwndbg.commands.leakfind
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
        import pwndbg.commands.peda
        import pwndbg.commands.pie
        import pwndbg.commands.plist
        import pwndbg.commands.probeleak
        import pwndbg.commands.procinfo
        import pwndbg.commands.radare2
        import pwndbg.commands.reload
        import pwndbg.commands.retaddr
        import pwndbg.commands.rizin
        import pwndbg.commands.rop
        import pwndbg.commands.ropper
        import pwndbg.commands.search
        import pwndbg.commands.segments
        import pwndbg.commands.shell
        import pwndbg.commands.sigreturn
        import pwndbg.commands.slab
        import pwndbg.commands.spray
        import pwndbg.commands.start
        import pwndbg.commands.telescope
        import pwndbg.commands.tips
        import pwndbg.commands.tls
        import pwndbg.commands.valist
        import pwndbg.commands.version
        import pwndbg.commands.vmmap
        import pwndbg.commands.windbg
        import pwndbg.commands.xinfo
        import pwndbg.commands.xor
