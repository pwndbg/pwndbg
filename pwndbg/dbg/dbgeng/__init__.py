import contextlib
import shlex
from typing import Any, Callable, Iterator, List, Literal, Tuple, TypeVar
from pybag.dbgeng.idebugclient import DebugClient
from pybag.dbgeng.idebugsystemobjects import DebugSystemObjects
from pybag.dbgeng.idebugregisters import DebugRegisters
from pybag.dbgeng.idebugcontrol import DebugControl
from pybag.dbgeng.dbgengstructs import DebugValue
from typing_extensions import override

import pwndbg
from pwndbg.dbg import selection
from pwndbg.aglib import load_aglib
from pwndbg.dbg.dbgeng.dispatch import CommandDispatcher

T = TypeVar("T")


dbgclient: DebugClient
dbgcontrol: DebugControl
dbgsysobjects: DebugSystemObjects
dbgregisters: DebugRegisters


class SelectionMixin:
    def select(self):
        """
        Selects the current object in the global debugger state.
        """
        raise NotImplementedError()


def selected(func):
    """
    Decorator that selects the current object.
    """
    def wrapper(self, *args, **kwargs):
        with self.select():
            return func(self, *args, **kwargs)
    return wrapper


class DbgEngCommandHandle(pwndbg.dbg_mod.CommandHandle):
    pass


class DbgEngRegisters(pwndbg.dbg_mod.Registers):
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        index = dbgregisters.GetIndexByName(name)
        return DbgEngValue(dbgregisters.GetValue(index))


class DbgEngFrame(pwndbg.dbg_mod.Frame):
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return DbgEngRegisters()


class DbgEngThread(SelectionMixin, pwndbg.dbg_mod.Thread):
    def __init__(self, thread_id: int):
        self.thread_id = thread_id

    @override
    def select(self):
        return selection(self.thread_id, lambda: dbgsysobjects.GetCurrentThreadId(),
                         lambda t: dbgsysobjects.SetCurrentThreadId(t))

    @override
    @contextlib.contextmanager
    @selected
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        yield DbgEngFrame()


class DbgEngProcess(SelectionMixin, pwndbg.dbg_mod.Process):
    def __init__(self, process_id: int):
        self.process_id = process_id

    def select(self):
        return selection(self.process_id, lambda: dbgsysobjects.GetCurrentProcessId(),
                         lambda p: dbgsysobjects.SetCurrentProcessId(p))

    @override
    @selected
    def threads(self) -> List[pwndbg.dbg_mod.Thread]:
        return [
            DbgEngThread(thread_id=thread_id)
            for thread_id in dbgsysobjects.GetThreadIdsByIndex()[0]
        ]

    @override
    def pid(self) -> int | None:
        return self.process_id

    @override
    def alive(self) -> bool:
        return dbgsysobjects.GetProcessIdBySystemId(self.process_id) is not None

    @override
    @selected
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value | None:
        dbgcontrol.Evaluate(expression)
        

class DbgEngValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: DebugValue):
        self.inner = inner

    @override
    def __int__(self) -> int:
        return self.inner.get_value()


class DbgEng(pwndbg.dbg_mod.Debugger):
    command_dispatcher: CommandDispatcher

    @override
    def setup(self, command_dispatcher: CommandDispatcher) -> None:
        self.command_dispatcher = command_dispatcher

        from pwndbg.commands import load_commands

        load_aglib()

        # Load all commands
        load_commands()

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # WinDbg does not provide an easy way to retrieve command history.
        return []

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return shlex.split(command_line)

    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        raise NotImplementedError()

    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        raise NotImplementedError()

    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        raise NotImplementedError()

    @override
    def commands(self) -> List[str]:
        return []

    @override
    def add_command(
        self,
        command_name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
        doc: str | None,
    ) -> pwndbg.dbg_mod.CommandHandle:
        self.command_dispatcher.register(command_name, handler)
        return DbgEngCommandHandle()

    def has_event_type(self, ty: pwndbg.dbg_mod.EventType) -> bool:
        """
        Whether the given event type is supported by this debugger. Indicates
        that a user either can or cannot register an event handler of this type.
        """
        raise NotImplementedError()

    @override
    def event_handler(self, ty: pwndbg.dbg_mod.EventType) -> Callable[[Callable[..., T]], Callable[..., T]]:
        def decorator(fn: Callable[..., T]) -> Callable[..., T]:
            pass
        return decorator

    @contextlib.contextmanager
    def ctx_suspend_events(self, ty:pwndbg.dbg_mod.EventType) -> Iterator[None]:
        """
        Context manager for temporarily suspending and resuming the delivery of events
        of a given type.
        """

        self.suspend_events(ty)
        try:
            yield
        finally:
            self.resume_events(ty)

    def suspend_events(self, ty: pwndbg.dbg_mod.EventType) -> None:
        """
        Suspend delivery of all events of the given type until it is resumed
        through a call to `resume_events`.

        Events triggered during a suspension will be ignored, and will not be
        delived, even after delivery is resumed.
        """
        raise NotImplementedError()

    def resume_events(self, ty: pwndbg.dbg_mod.EventType) -> None:
        """
        Resume the delivery of all events of the given type, if previously
        suspeded through a call to `suspend_events`. Does nothing if the
        delivery has not been previously suspeded.
        """
        raise NotImplementedError()

    def set_sysroot(self, sysroot: str) -> bool:
        """
        Sets the system root for this debugger.
        """
        raise NotImplementedError()

    def x86_disassembly_flavor(self) -> Literal["att", "intel"]:
        """
        The flavor of disassembly to use for x86 targets.
        """
        raise NotImplementedError()

    def supports_breakpoint_creation_during_stop_handler(self) -> bool:
        """
        Whether breakpoint or watchpoint creation through `break_at` is
        supported during breakpoint stop handlers.
        """
        raise NotImplementedError()

    def breakpoint_locations(self) -> List[pwndbg.dbg_mod.BreakpointLocation]:
        raise NotImplementedError()

    @override
    def name(self) -> pwndbg.dbg_mod.DebuggerType:
        return pwndbg.dbg_mod.DebuggerType.DbgEng

    @override
    def is_gdblib_available(self) -> bool:
        return False

    def string_limit(self) -> int:
        raise NotImplementedError()

    def addrsz(self, address: Any) -> str:
        raise NotImplementedError()

    def get_cmd_window_size(self) -> Tuple[int, int]:
        raise NotImplementedError()

    @property
    def pre_ctx_lines(self) -> int:
        raise NotImplementedError()

    def set_python_diagnostics(self, enabled: bool) -> None:
        raise NotImplementedError()
