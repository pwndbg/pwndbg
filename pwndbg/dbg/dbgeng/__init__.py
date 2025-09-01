import contextlib
import ctypes
from comtypes import COMError, hresult
import comtypes.gen.DbgEng as COM_DbgEng
import shlex
from typing import Any, Callable, Iterator, List, Literal, Sequence, Tuple, TypeVar
from pybag.dbgeng.idebugclient import DebugClient
from pybag.dbgeng.idebugsystemobjects import DebugSystemObjects
from pybag.dbgeng.idebugregisters import DebugRegisters
from pybag.dbgeng.idebugcontrol import DebugControl
from pybag.dbgeng.dbgengstructs import DebugValue
from typing_extensions import override

import pwndbg
from pwndbg.aglib import load_aglib
from pwndbg.dbg import selection
from pwndbg.dbg.dbgeng.events import EventCallback
from pwndbg.dbg.dbgeng.wrapper.systemobjects import DebugSystemObjects
from pwndbg.dbg.dbgeng.wrapper.control import DebugControl
from pwndbg.dbg.dbgeng.wrapper.registers import DebugRegisters
from pwndbg.dbg.dbgeng.wrapper.advanced import DebugAdvanced
from pwndbg.dbg.dbgeng.wrapper.symbols import DebugSymbols
from pwndbg.dbg.dbgeng.wrapper.wdbgexts import _EXT_TYPED_DATA, _DEBUG_TYPED_DATA, EXT_TDOP_SET_FROM_EXPR

T = TypeVar("T")


dbgclient: DebugClient
dbgcontrol: DebugControl
dbgsysobjects: DebugSystemObjects
dbgregisters: DebugRegisters
dbgadvanced: DebugAdvanced
dbgsymbols: DebugSymbols


def _evaluate(expression: str):
    extra = len(expression) + 1 # null terminator
    buffer = (ctypes.c_char * (ctypes.sizeof(_EXT_TYPED_DATA) + extra))()
    data = _EXT_TYPED_DATA.from_buffer(buffer)
    data.Operation = EXT_TDOP_SET_FROM_EXPR
    data.Flags = 0
    data.InStrIndex = ctypes.sizeof(_EXT_TYPED_DATA)

    ctypes.memmove(ctypes.addressof(buffer) + data.InStrIndex, expression.encode(), len(expression))

    dbgadvanced.Request(COM_DbgEng.DEBUG_REQUEST_EXT_TYPED_DATA_ANSI, buffer, len(buffer), buffer, len(buffer))
    return data


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


class CommandDispatcher:
    debugger: pwndbg.dbg_mod.Debugger
    handlers: dict[str, Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]]

    def __init__(self, debugger: pwndbg.dbg_mod.Debugger):
        self.debugger = debugger
        self.handlers = {}

    def register(self, command_name: str, handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]):
        self.handlers[command_name] = handler

    def dispatch(self, command_name: str, args: str):
        assert command_name in self.handlers
        handler = self.handlers[command_name]
        handler(self.debugger, args, True) # True indicates interactive


class DbgEngCommandHandle(pwndbg.dbg_mod.CommandHandle):
    pass


class DbgEngRegisters(pwndbg.dbg_mod.Registers):
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        index = dbgregisters.GetIndexByName(name)
        return DbgEngValue(dbgregisters.GetValue(index))


class DbgEngFrame(pwndbg.dbg_mod.Frame):
    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return DbgEngRegisters()


class DbgEngThread(SelectionMixin, pwndbg.dbg_mod.Thread):
    _tid: int   # The thread ID
    _etid: int  # The engine thread ID (the internal ID used by DbgEng)

    def __init__(self, tid: int, etid: int):
        self._tid = tid
        self._etid = etid

    @override
    def select(self):
        return selection(self._etid, lambda: dbgsysobjects.GetCurrentThreadId(),
                         lambda t: dbgsysobjects.SetCurrentThreadId(t))

    @override
    @contextlib.contextmanager
    @selected
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        yield DbgEngFrame()


class DbgEngProcess(SelectionMixin, pwndbg.dbg_mod.Process):
    _pid: int   # The process ID
    _epid: int  # The engine process ID (the internal ID used by DbgEng)

    def __init__(self, pid: int, epid: int):
        self._pid = pid
        self._epid = epid

    def select(self):
        return selection(self._epid, lambda: dbgsysobjects.GetCurrentProcessId(),
                         lambda p: dbgsysobjects.SetCurrentProcessId(p))

    @override
    @selected
    def threads(self) -> List[pwndbg.dbg_mod.Thread]:
        return [
            DbgEngThread(tid, etid)
            for etid, tid in zip(dbgsysobjects.GetThreadIdsByIndex())
        ]

    @override
    def pid(self) -> int | None:
        return self._pid

    @override
    def alive(self) -> bool:
        try:
            return dbgsysobjects.GetProcessIdBySystemId(self._pid) == self._epid
        except COMError as e:
            if e.hresult == hresult.E_NOINTERFACE:
                return False
            raise

    @override
    @selected
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value | None:
        # TODO
        dbgcontrol.Evaluate(expression)
    
    @override
    @selected
    def is_remote(self) -> bool:
        # GetDebuggeeType returns the class and qualifier of the debuggee.
        # The class can be one of:
        # - DEBUG_CLASS_KERNEL
        # - DEBUG_CLASS_USER_WINDOWS
        # - DEBUG_CLASS_UNINITIALIZED
        debuggee_class, debuggee_qualifier = dbgcontrol.GetDebuggeeType()
        if debuggee_class == COM_DbgEng.DEBUG_CLASS_KERNEL:
            # All other options are either local or dump files
            return debuggee_qualifier in (
                COM_DbgEng.DEBUG_KERNEL_CONNECTION,
                COM_DbgEng.DEBUG_KERNEL_EXDI_DRIVER
            )
        elif debuggee_class == COM_DbgEng.DEBUG_CLASS_USER_WINDOWS:
            # All other options are either local or dump files
            return debuggee_qualifier == COM_DbgEng.DEBUG_USER_WINDOWS_PROCESS_SERVER
        
        # There is no target
        return False
    
    @override
    @selected
    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        try:
            module_base, type_id = dbgsymbols.GetSymbolTypeId(name)
        except COMError as e:
            if e.hresult == hresult.E_FAIL:
                return []
            raise
        return [DbgEngType(module_base, type_id)]
    
    @override
    @selected
    def is_linux(self) -> bool:
        # DbgEng only supports Windows targets
        return False


class DbgEngType(pwndbg.dbg_mod.Type):
    module_base: int    # Base address of the module containing this type
    type_id: int        # Type ID of this type

    def __init__(self, module_base: int, type_id: int):
        self.module_base = module_base
        self.type_id = type_id

    @property
    @override
    def sizeof(self) -> int:
        return dbgsymbols.GetTypeSize(self.module_base, self.type_id)


class DbgEngValue(pwndbg.dbg_mod.Value):
    inner: _DEBUG_TYPED_DATA

    def __init__(self, inner: _DEBUG_TYPED_DATA):
        self.inner = inner

    @override
    @property
    def type(self) -> pwndbg.dbg_mod.Type:
        return DbgEngType(self.inner.ModBase, self.inner.TypeId)


class DbgEng(pwndbg.dbg_mod.Debugger):
    command_dispatcher: CommandDispatcher
    event_callback: EventCallback

    @override
    def setup(self, command_dispatcher: CommandDispatcher) -> None:
        self.command_dispatcher = command_dispatcher

        # Setup event callbacks
        self.event_callback = EventCallback()
        dbgclient.SetEventCallbacks(self.event_callback)

        import pwndbg
        from pwndbg.commands import load_commands

        load_aglib()

        # Load all commands
        load_commands()

        # Register hooks
        import pwndbg.dbg.dbgeng.hooks

        # Manually trigger the START event
        self.event_callback._trigger_event(pwndbg.dbg_mod.EventType.START)

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # TODO: Implement command history if possible.
        # The history seems to be handled by the debugger frontend (e.g., WinDbg)
        return []

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return shlex.split(command_line)

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        pid = dbgsysobjects.GetCurrentProcessSystemId()
        epid = dbgsysobjects.GetCurrentProcessId()
        return DbgEngProcess(pid, epid)

    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        raise NotImplementedError()

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        return DbgEngFrame()

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
            self.event_callback._register_event(ty, fn)
            return fn
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
