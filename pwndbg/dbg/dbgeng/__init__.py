import contextlib
import ctypes
from comtypes import COMError, hresult
from comtypes.automation import VT_I1, VT_UI1, VT_I2, VT_UI2, VT_I4, VT_UI4, VT_I8, VT_UI8, VT_INT, VT_UINT
from pwndbg.dbg.dbgeng.wrapper.dbgeng import DbgEng as COM_DbgEng
from pwndbg.dbg.dbgeng.wrapper.dbgmodel import DbgModel
import shlex
from typing import Any, Callable, Iterator, List, Literal, Sequence, Tuple, TypeVar
from typing_extensions import override
import os

import pwndbg
from pwndbg.aglib import load_aglib
from pwndbg.dbg import selection
from pwndbg.dbg.dbgeng.events import EventCallback
from pwndbg.dbg.dbgeng.wrapper.dbgeng import DebugSystemObjects, DebugClient, DebugControl, DebugRegisters, \
    DebugAdvanced, DebugSymbols, DebugDataSpaces
from pwndbg.dbg.dbgeng.wrapper.dbgmodel import DebugHost, HostDataModelAccess, DataModelManager, DebugHostSymbols, \
    DebugHostType, ModelObject, DebugHostEvaluator, DebugHostMemory, USE_CURRENT_HOST_CONTEXT
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
dbgdataspaces: DebugDataSpaces

hostdatamodelaccess: HostDataModelAccess
datamodelmanager: DataModelManager
debughost: DebugHost
debughostsymbols: DebugHostSymbols
debughostevaluator: DebugHostEvaluator
debughostmemory: DebugHostMemory


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
        if name == "pc":
            # For compatibility with gdb
            # FIXME: This assumes x86-64
            name = "rip"
        obj = self.inner.GetKeyValue(name)
        if obj is None:
            return None
        obj, _ = obj    # metadata
        return DbgEngValue(obj) if obj is not None else None


class DbgEngFrame(pwndbg.dbg_mod.Frame):
    thread: "DbgEngThread"
    inner: ModelObject

    def __init__(self, thread: "DbgEngThread", inner: ModelObject):
        self.thread = thread
        self.inner = inner

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        # Debugger.State.DebuggerVariables.curthread.Registers.User
        obj, _ = self.thread.inner.GetKeyValue("Registers")
        user_regs, _ = obj.GetKeyValue("User")
        return DbgEngRegisters(user_regs)

    @override
    def pc(self) -> int:
        attributes, _ = self.inner.GetKeyValue("Attributes")
        value, _ = attributes.GetKeyValue("InstructionOffset")
        return int(DbgEngValue(value))

    @override
    def parent(self) -> pwndbg.dbg_mod.Frame | None:
        # TODO: implement this
        return None

    @override
    def child(self) -> pwndbg.dbg_mod.Frame | None:
        # TODO: implement this
        return None

    @override
    def sal(self) -> Tuple[str, int] | None:
        # TODO: implement this
        return None

    @override
    def __eq__(self, rhs: object) -> bool:
        assert isinstance(rhs, DbgEngFrame)
        rhs: DbgEngFrame = rhs

        return self.inner.GetContext().IsEqualTo(rhs.inner.GetContext())


class DbgEngThread(pwndbg.dbg_mod.Thread):
    inner: ModelObject

    def __init__(self, inner: ModelObject):
        self.inner = inner

    @override
    @contextlib.contextmanager
    def bottom_frame(self) -> Iterator[pwndbg.dbg_mod.Frame]:
        stack, _ = self.inner.GetKeyValue("Stack")
        concept, _ = stack.IterableConcept()
        iterator = concept.GetIterator(stack)
        item = iterator.GetNext()
        if item is not None:
            yield DbgEngFrame(self, item)


class DbgEngMemoryMap(pwndbg.dbg_mod.MemoryMap):
    @override
    def is_qemu(self) -> bool:
        # FIXME: Implement this if possible.
        return False


class DbgEngProcess(pwndbg.dbg_mod.Process):
    inner: ModelObject

    def __init__(self, dbg: "DbgEng", inner: ModelObject):
        self.dbg = dbg
        self.inner = inner

    @override
    def threads(self) -> List[pwndbg.dbg_mod.Thread]:
        # Debugger.State.DebuggerVariables.curprocess.Threads
        obj,_ = self.inner.GetKeyValue("Threads")
        concept, _ = obj.IterableConcept()
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
    def vmmap(self) -> pwndbg.dbg_mod.MemoryMap:
        pages = list(self.get_pages())
        return DbgEngMemoryMap(pages)

    def get_pages(self) -> Iterator[pwndbg.lib.memory.Page]:
        # TODO: This part might introduce race, consider using IDebugHostContextControl
        engine_pid = dbgsysobjects.GetProcessIdBySystemId(self.pid())
        dbgsysobjects.SetCurrentProcessId(engine_pid)

        pages = []
        offset = 0
        while True:
            info = dbgdataspaces.QueryVirtual(offset)
            if info is None:
                break

            # Next offset
            offset = info.BaseAddress + info.RegionSize

            if info.State & MEM_FREE:
                # MEM_FREE regions are not accessible
                continue

            # PAGE_WRITECOPY and PAGE_EXECUTE_WRITECOPY indicate CoW access
            flags = 0
            if any(info.Protect & flag for flag in (PAGE_EXECUTE_READ,
                                                    PAGE_EXECUTE_READWRITE,
                                                    PAGE_EXECUTE_WRITECOPY,
                                                    PAGE_READONLY,
                                                    PAGE_READWRITE,
                                                    PAGE_WRITECOPY)):
                flags |= os.R_OK
            if any(info.Protect & flag for flag in (PAGE_EXECUTE_READWRITE,
                                                    PAGE_EXECUTE_WRITECOPY,
                                                    PAGE_READWRITE,
                                                    PAGE_WRITECOPY)):
                flags |= os.W_OK
            if any(info.Protect & flag for flag in (PAGE_EXECUTE,
                                                    PAGE_EXECUTE_READ,
                                                    PAGE_EXECUTE_READWRITE,
                                                    PAGE_EXECUTE_WRITECOPY)):
                flags |= os.X_OK

            yield pwndbg.lib.memory.Page(
                info.BaseAddress,
                info.RegionSize,
                flags,
                info.AllocationBase,
            )

    @override
    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        # TODO: implement this
        location = DbgModel._Location(0, address)
        mem = debughostmemory.ReadBytes(self.inner.GetContext(), location, size)
        if len(mem) < size and not partial:
            raise pwndbg.dbg_mod.Error(f"unable to read {size:#x} bytes")
        return bytearray(mem)

    @override
    def is_remote(self) -> bool:
        # TODO: This is the old implementation. Use the new Debugger Data Model for the new one.
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
        # Debugger.State.DebuggerVariables.cursession.Attributes.Machine
        session, _ = self.dbg.inner.GetKeyValue("cursession")
        attribute, _ = session.GetKeyValue("Attributes")
        machine, _ = attribute.GetKeyValue("Machine")
        ptrsize = machine.GetKeyValue("PointerSize")[0].GetIntrinsicValueAs(VT_UI4).value
        endian = "big" if machine.GetKeyValue("IsBigEndian")[0].GetIntrinsicValueAs(VT_UI4).value else "little"
        platform = Platform.WINDOWS # FIXME: does DbgEng support other platforms?

        # TODO: @$cursession.Attributes.Machine exposes two fields: FullName and AbbrevName which
        # indicate the architecture. However there are two issues right now:
        # 1. No documentation about the possible values (might require reverse engineering)
        # 2. Effective arch might be different from the physical arch (e.g., WOW64)
        # For now we just assume x86-64
        return ArchDefinition(name="x86-64", ptrsize=ptrsize, endian=endian, platform=platform)

    @override
    def symbol_name_at_address(self, address: int) -> str | None:
        # TODO: implement this
        return None

    @override
    def is_linux(self) -> bool:
        # DbgEng only supports Windows targets (FIXME: verify this)
        return False


class DbgEngType(pwndbg.dbg_mod.Type):
    inner: DebugHostType

    def __init__(self, inner: DebugHostType):
        self.inner = inner
        self.is_intrinsic = (self.inner.GetTypeKind() == DbgModel.TypeIntrinsic)
        if self.is_intrinsic:
            self.kind, self.carrier = self.inner.GetIntrinsicType()

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

    @override
    def __int__(self) -> int:
        return self.inner.GetIntrinsicValue().value

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        assert isinstance(type, DbgEngType)
        type: DbgEngType = type

        # TODO: Currently, casting only works for intrinsic types.
        assert type.is_intrinsic
        variant = self.inner.GetIntrinsicValueAs(type.carrier)
        return DbgEngValue(datamodelmanager.CreateIntrinsicObject(DbgModel.ObjectIntrinsic, variant))


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
        # Debugger.State.DebuggerVariables.curframe
        return DbgEngFrame(self.selected_thread(), self.inner.GetKeyValue("curframe")[0])

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

    @override
    def x86_disassembly_flavor(self) -> Literal["att", "intel"]:
        # TODO: Implement this if possible.
        return "intel"

    @override
    def breakpoint_locations(self) -> List[pwndbg.dbg_mod.BreakpointLocation]:
        # TODO: Implement this
        return []

    @override
    def name(self) -> pwndbg.dbg_mod.DebuggerType:
        return pwndbg.dbg_mod.DebuggerType.DbgEng

    @override
    def is_gdblib_available(self) -> bool:
        return False

    @override
    def addrsz(self, address: Any) -> str:
        return "%#16x" % address

    @override
    @property
    def pre_ctx_lines(self) -> int:
        # DbgEng usually prints 2 lines
        # ntdll!LdrpDoDebuggerBreak+0x31:
        # 00007ffa`cc480731 eb00            jmp     ntdll!LdrpDoDebuggerBreak+0x33 (00007ffa`cc480733)
        return 2
