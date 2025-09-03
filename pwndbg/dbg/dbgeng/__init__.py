import contextlib
import ctypes
from comtypes import COMError, hresult
from comtypes.automation import VT_I1, VT_UI1, VT_I2, VT_UI2, VT_I4, VT_UI4, VT_I8, VT_UI8, VT_INT, VT_UINT
from pwndbg.dbg.dbgeng.wrapper.dbgeng import DbgEng as COM_DbgEng
from pwndbg.dbg.dbgeng.wrapper.dbgmodel import DbgModel
import shlex
from typing import Any, Callable, Iterator, List, Literal, Sequence, Tuple, TypeVar
from typing_extensions import override

import pwndbg
from pwndbg.aglib import load_aglib
from pwndbg.dbg import selection
from pwndbg.dbg.dbgeng.events import EventCallback
from pwndbg.dbg.dbgeng.wrapper.dbgeng import DebugSystemObjects, DebugClient, DebugControl, DebugRegisters, \
    DebugAdvanced, DebugSymbols
from pwndbg.dbg.dbgeng.wrapper.dbgmodel import DebugHost, HostDataModelAccess, DataModelManager, DebugHostSymbols, \
    DebugHostType, ModelObject, DebugHostEvaluator, USE_CURRENT_HOST_CONTEXT
from pwndbg.dbg.dbgeng.wrapper.wdbgexts import _EXT_TYPED_DATA, _DEBUG_TYPED_DATA
from pwndbg.dbg.dbgeng.wrapper.constants import *
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform
import pwndbg.aglib.typeinfo as typeinfo

T = TypeVar("T")


dbgclient: DebugClient
dbgcontrol: DebugControl
dbgsysobjects: DebugSystemObjects
dbgregisters: DebugRegisters
dbgadvanced: DebugAdvanced
dbgsymbols: DebugSymbols

hostdatamodelaccess: HostDataModelAccess
datamodelmanager: DataModelManager
debughost: DebugHost
debughostsymbols: DebugHostSymbols
debughostevaluator: DebugHostEvaluator


def _get_typed_data(module_base: int, type_id: int, ptr = False, tag: int = 0) -> _DEBUG_TYPED_DATA:
    print(module_base, type_id, ptr, tag)
    buffer = (ctypes.c_char * ctypes.sizeof(_EXT_TYPED_DATA))()
    data = _EXT_TYPED_DATA.from_buffer(buffer)
    if ptr:
        data.Operation = EXT_TDOP_SET_PTR_FROM_TYPE_ID_AND_U64
    else:
        data.Operation = EXT_TDOP_SET_FROM_TYPE_ID_AND_U64
    data.Flags = 0

    data.InData.ModBase = module_base
    data.InData.TypeId = type_id
    data.InData.Tag = tag

    dbgadvanced.Request(COM_DbgEng.DEBUG_REQUEST_EXT_TYPED_DATA_ANSI,
                        buffer,
                        len(buffer),
                        buffer,
                        len(buffer))
    return data.OutData


def _typed_data_op(op: int, *, flags: int = 0, in_data: _DEBUG_TYPED_DATA = None, in_str: str = None, in_value: int = 0,
                   out_len: int = 0)-> tuple[str, int, bytes]:
    """
    Perform a suboperation on typed data.
    https://github.com/MicrosoftDocs/windows-driver-docs/blob/06bb50abad3a39c371b54a02004839d8d1fc005f/windows-driver-docs-pr/debugger/debug-request-ext-typed-data-ansi.md
    """

    ext_data_len = ctypes.sizeof(_EXT_TYPED_DATA) + out_len
    if in_str is not None:
        ext_data_len += len(in_str) + 1 # null terminator

    buffer = (ctypes.c_char * ext_data_len)()
    extra_offset = ctypes.sizeof(_EXT_TYPED_DATA)

    ext_data = _EXT_TYPED_DATA.from_buffer(buffer)
    ext_data.Operation = op
    ext_data.Flags = flags
    if in_data is not None:
        ext_data.InData = in_data

    if in_str is not None:
        ext_data.InStrIndex = extra_offset
        ctypes.memmove(ctypes.addressof(buffer) + ext_data.InStrIndex, in_str.encode(), len(in_str))
        extra_offset += len(in_str) + 1

    ext_data.In64 = in_value
    if out_len > 0:
        ext_data.StrBufferIndex = extra_offset
        ext_data.StrBufferChars = out_len
        extra_offset += out_len


    dbgadvanced.Request(COM_DbgEng.DEBUG_REQUEST_EXT_TYPED_DATA_ANSI,
                        buffer,
                        len(buffer),
                        buffer,
                        len(buffer))
    # Retry
    if out_len > 0 and ext_data.StrCharsNeeded > out_len:
        out_len = ext_data.StrCharsNeeded
        return _typed_data_op(op, flags=flags, in_data=in_data, in_str=in_str, in_value=in_value, out_len=out_len)

    out_str = None
    if out_len > 0:
        out_str = ctypes.string_at(ctypes.addressof(buffer) + ext_data.StrBufferIndex, ext_data.StrCharsNeeded).decode()

    out_value = ext_data.Out32
    full_result = bytes(buffer)
    return out_str, out_value, full_result


class TypedDataWrapper:
    def __init__(self, data: _DEBUG_TYPED_DATA):
        self.data = data

    def sizeof(self) -> int:
        _, size, _ = _typed_data_op(EXT_TDOP_GET_TYPE_SIZE, in_data=self.data)
        return size
    
    def pointer(self) -> "TypedDataWrapper":
        _, _, buffer = _typed_data_op(EXT_TDOP_GET_POINTER_TO, in_data=self.data)
        return TypedDataWrapper(_DEBUG_TYPED_DATA.from_buffer_copy(buffer, _EXT_TYPED_DATA.OutData.offset))
    
    @classmethod
    def from_type_id(cls, module_base: int, type_id: int) -> "TypedDataWrapper":
        data = _DEBUG_TYPED_DATA()
        data.ModBase = module_base
        data.TypeId = type_id
        data.Offset = 0
        _, _, buffer = _typed_data_op(EXT_TDOP_SET_FROM_TYPE_ID_AND_U64, in_data=data)
        return cls(_DEBUG_TYPED_DATA.from_buffer_copy(buffer, _EXT_TYPED_DATA.OutData.offset))
    
    @classmethod
    def from_expression(cls, expression: str) -> "TypedDataWrapper":
        _, _, buffer = _typed_data_op(EXT_TDOP_SET_FROM_EXPR, in_str=expression)
        return cls(_DEBUG_TYPED_DATA.from_buffer_copy(buffer, _EXT_TYPED_DATA.OutData.offset))

    def __del__(self):
        _typed_data_op(EXT_TDOP_RELEASE, in_data=self.data)


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
    inner: ModelObject

    def __init__(self, inner: ModelObject):
        self.inner = inner

    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        obj, _ = self.inner.GetKeyValue(name)
        return DbgEngValue(obj) if obj is not None else None


class DbgEngFrame(pwndbg.dbg_mod.Frame):
    thread: "DbgEngThread"
    inner: ModelObject

    def __init__(self, thread: "DbgEngThread", inner: ModelObject):
        self.thread = thread
        self.inner = inner

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        obj, _ = self.thread.inner.GetKeyValue("Registers")
        user_regs, _ = obj.GetKeyValue("User")
        return DbgEngRegisters(user_regs)


class DbgEngThread(pwndbg.dbg_mod.Thread):
    inner: ModelObject

    def __init__(self, inner: ModelObject):
        self.inner = inner

    @override
    @contextlib.contextmanager
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        yield DbgEngFrame(self, None)


class DbgEngProcess(pwndbg.dbg_mod.Process):
    inner: ModelObject

    def __init__(self, dbg: "DbgEng", inner: ModelObject):
        self.dbg = dbg
        self.inner = inner

    @override
    def threads(self) -> List[pwndbg.dbg_mod.Thread]:
        obj,_ = self.inner.GetKeyValue("Threads")
        concept = obj.IterableConcept()
        iterator = concept.GetIterator(obj)

        threads = []
        while True:
            item = iterator.GetNext()
            if item is None:
                break
            threads.append(DbgEngThread(item))
        return threads

    @override
    def pid(self) -> int | None:
        # TODO: I'm not sure what happens if the process is dead.
        obj,_ = self.inner.GetKeyValue("Id")

        # Windows PIDs are 32-bit unsigned integers
        variant = obj.GetIntrinsicValueAs(VT_UI4)
        return variant.value

    @override
    def alive(self) -> bool:
        # DbgEng does not provide a direct way to check if the process is alive.
        # However it seems that DbgEng doesn't work with dead processes.
        return True

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value | None:
        # TODO
        dbgcontrol.Evaluate(expression)
    
    @override
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
    def types_with_name(self, name: str) -> Sequence[pwndbg.dbg_mod.Type]:
        # Iterates through all modules and finds types with the given name.
        enumerator = debughostsymbols.EnumerateModules(self.inner.GetContext())
        candidates = []
        while True:
            symbol = enumerator.GetNext()
            if symbol is None:
                break
            try:
                module = symbol.DebugHostModule()
                candidates.append(module.FindTypeByName(name))
            except COMError:
                continue
        return [DbgEngType(t) for t in candidates]

    @override
    def arch(self) -> ArchDefinition:
        # It seems that all architectures supported by DbgEng [1] are little-endian.
        # Let's assume that only Windows targets are supported (FIXME: verify this).
        # [1]: https://github.com/MicrosoftDocs/windows-driver-docs-ddi/blob/b3e1ec3d46d4231c7b1c514f27507e461a6b3b4d/wdk-ddi-src/content/dbgeng/nf-dbgeng-idebugcontrol3-getactualprocessortype.md
        # is_64bit = dbgcontrol.IsPointer64Bit()
        # ptrsize = 8 if is_64bit else 4
        # endian = "little"
        # platform = Platform.WINDOWS
        # processor_type = dbgcontrol.GetExecutingProcessorType()
        # if processor_type == IMAGE_FILE_MACHINE_I386:
        #     name = "i386"
        # elif processor_type == IMAGE_FILE_MACHINE_ARM:
        #     name = "arm"
        # elif processor_type == IMAGE_FILE_MACHINE_IA64:
        #     name = "ia64"
        # elif processor_type == IMAGE_FILE_MACHINE_AMD64:
        #     name = "x86-64"
        # elif processor_type == IMAGE_FILE_MACHINE_EBC:
        #     name = "ebc"
        # else:
        #     raise RuntimeError(f"Unknown processor type: {processor_type}")
        # return ArchDefinition(name=name, ptrsize=ptrsize, endian=endian, platform=platform)

        # Debugger.State.DebuggerVariables.cursession.Attributes.Machine
        session, _ = self.dbg.inner.GetKeyValue("cursession")
        attribute, _ = session.GetKeyValue("Attributes")
        machine, _ = attribute.GetKeyValue("Machine")
        ptrsize = machine.GetKeyValue("PointerSize")[0].GetIntrinsicValueAs(VT_UI4).value
        endian = "big" if machine.GetKeyValue("IsBigEndian")[0].GetIntrinsicValueAs(VT_UI4).value else "little"
        platform = Platform.WINDOWS
        return ArchDefinition(name="x86-64", ptrsize=ptrsize, endian=endian, platform=platform)

    @override
    def is_linux(self) -> bool:
        # DbgEng only supports Windows targets (FIXME: verify this)
        return False


class DbgEngType(pwndbg.dbg_mod.Type):
    inner: DebugHostType

    def __init__(self, inner: DebugHostType):
        self.inner = inner

    @property
    @override
    def sizeof(self) -> int:
        return self.inner.GetSize()

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        # PointerStandard indicates a standard C/C++ pointer (*)
        # The specification could be found at [1]
        # [1]: https://github.com/MicrosoftDocs/windows-driver-docs-ddi/blob/b3e1ec3d46d4231c7b1c514f27507e461a6b3b4d/wdk-ddi-src/content/dbgmodel/ne-dbgmodel-pointerkind.md
        return DbgEngType(self.inner.CreatePointerTo(DbgModel.PointerStandard))


class DbgEngValue(pwndbg.dbg_mod.Value):
    inner: ModelObject

    def __init__(self, inner: ModelObject):
        self.inner = inner

    @override
    @property
    def type(self) -> pwndbg.dbg_mod.Type:
        value_type = self.inner.GetTypeInfo()
        if value_type is None:
            # TODO: In some cases, the type is not available [1] (intrinsic types?)
            # [1]: https://github.com/MicrosoftDocs/windows-driver-docs-ddi/blob/b3e1ec3d46d4231c7b1c514f27507e461a6b3b4d/wdk-ddi-src/content/dbgmodel/nf-dbgmodel-imodelobject-gettypeinfo.md
            raw = self.inner.GetIntrinsicValue()
            if raw.vt == VT_I1:
                return typeinfo.int8
            elif raw.vt == VT_UI1:
                return typeinfo.uint8
            elif raw.vt == VT_I2:
                return typeinfo.int16
            elif raw.vt == VT_UI2:
                return typeinfo.uint16
            elif raw.vt == VT_I4:
                return typeinfo.int32
            elif raw.vt == VT_UI4:
                return typeinfo.uint32
            elif raw.vt == VT_I8:
                return typeinfo.int64
            elif raw.vt == VT_UI8:
                return typeinfo.uint64
            elif raw.vt == VT_INT:
                return typeinfo.sint
            elif raw.vt == VT_UINT:
                return typeinfo.uint
            else:
                raise RuntimeError(f"Unsupported intrinsic type: {raw.vt}")
        return DbgEngType(value_type)

    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        pass


def _get_root_dbgstate() -> ModelObject:
    # Get Debugger.State.DebuggerVariables from the root namespace
    root = datamodelmanager.GetRootNamespace()
    dbgstate = (root.GetKeyValue("Debugger")[0]
                   .GetKeyValue("State")[0]
                   .GetKeyValue("DebuggerVariables")[0])
    return dbgstate


class DbgEng(pwndbg.dbg_mod.Debugger):
    command_dispatcher: CommandDispatcher
    event_callback: EventCallback
    inner: ModelObject

    @override
    def setup(self, command_dispatcher: CommandDispatcher) -> None:
        self.command_dispatcher = command_dispatcher

        # Initialize the debugger state
        self.inner = _get_root_dbgstate()

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

        # TODO: In WinDbg, normally the extension is loaded after the target is attached.
        # Therefore the START event is triggered manually here.
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
        # Debugger.State.DebuggerVariables.curprocess
        return DbgEngProcess(self, self.inner.GetKeyValue("curprocess")[0])

    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        # Debugger.State.DebuggerVariables.curthread
        return DbgEngThread(self.inner.GetKeyValue("curthread")[0])

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        return DbgEngFrame(self.selected_thread(), None)

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
