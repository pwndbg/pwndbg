"""
The abstracted debugger interface.
"""

from __future__ import annotations

import contextlib
from enum import Enum
from typing import Any
from typing import Awaitable
from typing import Callable
from typing import Coroutine
from typing import Generator
from typing import Iterator
from typing import List
from typing import Literal
from typing import Sequence
from typing import Tuple
from typing import TypedDict
from typing import TypeVar

import pwndbg.lib.memory
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import ArchDefinition

dbg: Debugger = None

T = TypeVar("T")


@contextlib.contextmanager
def selection(target: T, get_current: Callable[[], T], select: Callable[[T], None]):
    """
    Debuggers have global state. Many of our queries require that we select a
    given object globally before we make them. When doing that, we must always
    be careful to return selection to its previous state before exiting. This
    class automatically manages the selection of a single object type.

    Upon entrace to the `with` block, the element given by `target` will be
    compared to the object returned by calling `get_current`. If they
    compare different, the value previously returned by `get_current` is
    saved, and the element given by `target` will be selected by passing it
    as an argument to `select`, and, after execution leaves the `with`
    block, the previously saved element will be selected in the same fashion
    as the first element.

    If the elements don't compare different, this is a no-op.
    """

    current = get_current()
    restore = False
    if current != target:
        select(target)
        restore = True

    try:
        yield
    finally:
        if restore:
            select(current)


class Error(Exception):
    pass


class DisassembledInstruction(TypedDict):
    addr: int
    asm: str
    length: int


class DebuggerType(Enum):
    GDB = 1
    LLDB = 2


class StopPoint:
    """
    The handle to either an insalled breakpoint or watchpoint.

    May be used in a `with` statement, in which case the stop point is
    automatically removed at the end of the statement. This allows for easy
    implementation of temporary breakpoints.
    """

    def remove(self) -> None:
        """
        Removes the breakpoint associated with this handle.
        """
        raise NotImplementedError()

    def set_enabled(self, enabled: bool) -> None:
        """
        Enables or disables this breakpoint.
        """
        raise NotImplementedError()

    def __enter__(self) -> StopPoint:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        """
        Automatic breakpoint removal.
        """
        self.remove()


class BreakpointLocation:
    """
    This is the location specification for a breakpoint.
    """

    address: int

    def __init__(self, address: int):
        self.address = address

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BreakpointLocation):
            return self.address == other.address
        if isinstance(other, int):
            return self.address == other
        return False


class WatchpointLocation:
    """
    This is the location specification for a watchpoint.
    """

    address: int
    size: int
    watch_read: bool
    watch_write: bool

    def __init__(self, address: int, size: int, watch_read: bool, watch_write: bool):
        self.address = address
        self.size = size

        assert watch_read or watch_write, "Watchpoints must watch at least one of reads or writes"

        self.watch_read = watch_read
        self.watch_write = watch_write


class Registers:
    """
    A handle to the register values in a frame.
    """

    def by_name(self, name: str) -> Value | None:
        """
        Gets the value of a register if it exists, None otherwise.
        """
        raise NotImplementedError()


class SymbolLookupType(Enum):
    """
    Enum representing types of symbol lookups for filtering symbol searches.

    Attributes:
    - ANY: Represents searching for any symbol type (default).
    - FUNCTION: Represents searching specifically for function symbols.
    - VARIABLE: Represents searching specifically for variable symbols.
    """

    ANY = 1
    FUNCTION = 2
    VARIABLE = 3


class Frame:
    def lookup_symbol(
        self,
        name: str,
        *,
        type: SymbolLookupType = SymbolLookupType.ANY,
    ) -> Value | None:
        """
        Looks up and returns the address of a symbol in current frame by its name.

        Parameters:
        - name (str): The name of the symbol to look up.
        - type (SymbolLookupType, optional): The type of symbol to search for. Defaults
          to SymbolLookupType.ANY.

        Returns:
        - pwndbg.dbg_mod.Value | None: The value of the symbol if found, or None if not found.

        Raises:
        - pwndbg.dbg_mod.Error: If symbol name contains invalid characters
        """
        raise NotImplementedError()

    def evaluate_expression(self, expression: str, lock_scheduler: bool = False) -> Value:
        """
        Evaluate the given expression in the context of this frame, and
        return a `Value`.

        # `lock_scheduler`
        Additionally, callers of this function might specify that they want to
        enable scheduler locking during the evaluation of this expression. This
        is a GDB-only option, and is intended for cases in which the result
        would be incorrect without it enabled, when running in GDB. Other
        debuggers should ignore this parameter.
        """
        raise NotImplementedError()

    def regs(self) -> Registers:
        """
        Access the values of the registers in this frame.
        """
        raise NotImplementedError()

    def reg_write(self, name: str, val: int) -> bool:
        """
        Sets the value of the register with the given name to the given value.
        Returns true if the register exists, false othewise. Throws an exception
        if the register exists but cannot be written to.
        """
        raise NotImplementedError()

    def pc(self) -> int:
        """
        The value of the program counter for this frame.
        """
        raise NotImplementedError()

    def sp(self) -> int:
        """
        The value of the stack pointer for this frame.
        """
        raise NotImplementedError()

    def parent(self) -> Frame | None:
        """
        The parent frame of this frame, if it exists.
        """
        raise NotImplementedError()

    def child(self) -> Frame | None:
        """
        The child frame of this frame, if it exists.
        """
        raise NotImplementedError()

    def sal(self) -> Tuple[str, int] | None:
        """
        The filename of the source code file associated with this frame, and the
        line number associated with it, if available.
        """
        raise NotImplementedError()

    def __eq__(self, rhs: object) -> bool:
        """
        Whether this frame is the same as the given frame. Two frames are the
        same if they point to the same stack frame and have the same execution
        context.
        """
        raise NotImplementedError()


class Thread:
    @contextlib.contextmanager
    def bottom_frame(self) -> Iterator[Frame]:
        """
        Frame at the bottom of the call stack for this thread.
        """
        raise NotImplementedError()

    def ptid(self) -> int | None:
        """
        The PTID of this thread, if available.
        """
        raise NotImplementedError()

    def index(self) -> int:
        """
        The unique index of this thread from the perspective of the debugger.
        """
        raise NotImplementedError()


class MemoryMap:
    """
    A wrapper around a sequence of memory ranges
    """

    def is_qemu(self) -> bool:
        """
        Returns whether this memory map was generated from a QEMU target.
        """
        raise NotImplementedError()

    def ranges(self) -> Sequence[pwndbg.lib.memory.Page]:
        """
        Returns all ranges in this memory map.
        """
        raise NotImplementedError()


class ExecutionController:
    def single_step(self) -> Awaitable[None]:
        """
        Steps to the next instruction.

        Throws `CancelledError` if a breakpoint or watchpoint is hit, the program
        exits, or if any other unexpected event that diverts execution happens
        while fulfulling the step.
        """
        raise NotImplementedError()

    def cont(self, until: StopPoint) -> Awaitable[None]:
        """
        Continues execution until the given breakpoint or whatchpoint is hit.

        Throws `CancelledError` if a breakpoint or watchpoint is hit that is not
        the one given in `until`, the program exits, or if any other unexpected
        event happens.
        """
        raise NotImplementedError()


class Process:
    def threads(self) -> List[Thread]:
        """
        Returns a list containing the threads in this process.
        """
        raise NotImplementedError()

    def pid(self) -> int | None:
        """
        Returns the process ID of this process if it is alive.
        """
        raise NotImplementedError()

    def alive(self) -> bool:
        """
        Returns whether this process is alive.
        """
        raise NotImplementedError()

    def stopped_with_signal(self) -> bool:
        """
        Returns whether this process was stopped by a signal.
        """
        raise NotImplementedError()

    def evaluate_expression(self, expression: str) -> Value:
        """
        Evaluate the given expression in the context of the current process, and
        return a `Value`.
        """
        raise NotImplementedError()

    def vmmap(self) -> MemoryMap:
        """
        Returns the virtual memory map of this process.
        """
        raise NotImplementedError()

    def read_memory(self, address: int, size: int, partial: bool = False) -> bytearray:
        """
        Reads the requested number of bytes from the address given in the memory
        space of this process. Will read as many bytes as possible starting at
        that location, and returns how many were read.

        Throws an exception if reading fails and partial is False.
        """
        raise NotImplementedError()

    def write_memory(self, address: int, data: bytearray, partial: bool = False) -> int:
        """
        Writes as many bytes from the given data buffer as possible into the
        given address in the memory space of this process.

        Throws an exception if writing fails and partial is False.
        """
        raise NotImplementedError()

    def find_in_memory(
        self,
        pattern: bytearray,
        start: int,
        size: int,
        align: int,
        max_matches: int = -1,
        step: int = -1,
    ) -> Generator[int, None, None]:
        """
        Searches for a bit pattern in the memory space of the process. The bit
        pattern can be searched for in a given memory range, and with a given
        alignment. The maximum number of matches that will be generated is
        given by `max_matches`. A value of `max_matches` of `-1` will generate
        all matches.
        """
        raise NotImplementedError()

    def is_remote(self) -> bool:
        """
        Returns whether this process is a remote process connected to using the
        GDB remote debugging protocol.
        """
        raise NotImplementedError()

    def send_remote(self, packet: str) -> bytes:
        """
        Sends the given packet to the GDB remote debugging protocol server.
        Should only be called if `is_remote()` is true.
        """
        raise NotImplementedError()

    def send_monitor(self, cmd: str) -> str:
        """
        Sends the given monitor command to the GDB remote debugging protocol
        server. Should only be called if `is_remote()` is true.
        """
        raise NotImplementedError()

    def download_remote_file(self, remote_path: str, local_path: str) -> None:
        """
        Downloads the given file from the remote host and saves it to the local
        given path. Should only be called if `is_remote()` is true.
        """
        raise NotImplementedError()

    def create_value(self, value: int, type: Type | None = None) -> Value:
        """
        Create a new value in the context of this process, with the given value
        and, optionally, type. If no type is provided, one will be chosen
        automatically.
        """
        raise NotImplementedError()

    # We'll likely have to expand this into a Symbol class and change this to a
    # `symbol_at_address` function later on.
    def symbol_name_at_address(self, address: int) -> str | None:
        """
        Returns the name of the symbol at the given address in the program, if
        one exists.
        """
        raise NotImplementedError()

    def lookup_symbol(
        self,
        name: str,
        *,
        prefer_static: bool = False,
        type: SymbolLookupType = SymbolLookupType.ANY,
        objfile_endswith: str | None = None,
    ) -> Value | None:
        """
        Looks up and returns the address of a symbol by its name.

        Parameters:
        - name (str): The name of the symbol to look up.
        - prefer_static (bool, optional): If True, prioritize symbols in the static block,
          if supported by the debugger. Defaults to False.
        - type (SymbolLookupType, optional): The type of symbol to search for. Defaults
          to SymbolLookupType.ANY.
        - objfile_endswith (str | None, optional): If specified, limits the search to the
          first object file whose name ends with the provided string.

        Returns:
        - pwndbg.dbg_mod.Value | None: The value of the symbol if found, or None if not found.

        Raises:
        - pwndbg.dbg_mod.Error: If no object file matching the `objfile_endswith` pattern is found.
        """
        raise NotImplementedError()

    # There is an interesting counterpart to this method that exists at the
    # module level. Depending on how we want to implement support for multiple
    # modules, it might be interesting to repeat it there.
    def types_with_name(self, name: str) -> Sequence[Type]:
        """
        Returns a list of all types in this process that match the given name.
        """
        raise NotImplementedError()

    def arch(self) -> ArchDefinition:
        """
        The default architecture of this process.
        """
        raise NotImplementedError()

    def break_at(
        self,
        location: BreakpointLocation | WatchpointLocation,
        stop_handler: Callable[[StopPoint], bool] | None = None,
        internal: bool = False,
    ) -> StopPoint:
        """
        Install a breakpoint or watchpoint at the given location.

        The type of the location determines whether the newly created object
        is a watchpoint or a breakpoint. `BreakpointLocation` locations yield
        breakpoints, while `WatchpointLocation` locations yield watchpoints.

        Aditionally, one may specify a stop handler function, to be run when
        the breakpoint or whatchpoint is hit, and that determines whether
        execution should stop. With a return value of `True` being interpreted
        as a signal to stop, and a return value of `False` being interpreted as
        a signal to continue execution. The extent of the actions that may be
        taken during the stop handler is determined by the debugger.

        Marking a breakpoint or watchpoint as `internal` hints to the
        implementation that the created breakpoint or watchpoint should not be
        directly nameable by the user, and that it should not print any messages
        upon being triggered. Implementations should try to honor this hint,
        but they are not required to in case honoring it is either not possible
        or comes at a significant impact to performance.

        This function returns a handle to the newly created breakpoint or
        watchpoint.
        """
        raise NotImplementedError()

    # This is a fairly lazy solution. We would ideally support a more robust way
    # to query for ABIs, but Pwndbg currely only uses `show osabi` in GDB to
    # check for whether the target is running under Linux, so we only implement
    # that check.
    def is_linux(self) -> bool:
        """
        Returns whether the current ABI is GNU/Linux.
        """
        raise NotImplementedError()

    def disasm(self, address: int) -> DisassembledInstruction | None:
        """
        Returns the disassembled instruction at the given address in the address
        space of the running process, or `None` if there's no valid instruction
        at that address.
        """
        raise NotImplementedError()

    # We probably want to expose a better module interface in the future, but,
    # for now, this is good enough.
    def module_section_locations(self) -> List[Tuple[int, int, str, str]]:
        """
        Return a list of (address, size, section_name, module_name) tuples for
        the loaded sections in every module of this process.
        """
        raise NotImplementedError()

    def main_module_name(self) -> str | None:
        """
        Returns the name of the main module.

        On remote targets, this may be prefixed with "target:" string.
        """
        raise NotImplementedError()

    def main_module_entry(self) -> int | None:
        """
        Returns the entry point of the main module.
        """
        raise NotImplementedError()

    def is_dynamically_linked(self) -> bool:
        """
        Returns whether this process makes use of dynamically linked libraries.

        # `"dynamically linked"`
        What exactly it means to be "dynamically linked" here is a little
        ill-defined. Ideally, this function should return true if the process
        uses the default dynamic linker for the system, as that would better
        reflect whether the process uses dynamic linking.

        Currently, though, Pwndbg expects it to behave the same as a check for
        the string "No shared libraries loaded at this time." in the output of
        the `info dll` GDB command, which checks for the presence of other
        modules in the address space of the process, rather than whether or not
        the dynamic linker is used.

        We should probably sort this out in the future.
        """
        raise NotImplementedError()

    def dispatch_execution_controller(
        self, procedure: Callable[[ExecutionController], Coroutine[Any, Any, None]]
    ):
        """
        Queues up the given execution controller-based coroutine for execution,
        sometime between the calling of this function and the
        """
        raise NotImplementedError()


class TypeCode(Enum):
    """
    Broad categories of types.
    """

    INVALID = -1
    POINTER = 1
    ARRAY = 2
    STRUCT = 3
    TYPEDEF = 4
    UNION = 5
    INT = 6
    ENUM = 7
    FUNC = 8
    BOOL = 9


class TypeField:
    """
    The fields in a structured type.

    Currently this is just a mirror of `gdb.Field`.
    """

    def __init__(
        self,
        bitpos: int,
        name: str | None,
        type: Type,
        parent_type,
        enumval: int | None = None,
        artificial: bool = False,
        is_base_class: bool = False,
        bitsize: int = 0,
    ) -> None:
        self.bitpos = bitpos
        self.name = name
        self.type = type
        self.parent_type = parent_type
        self.enumval = enumval
        self.artificial = artificial
        self.is_base_class = is_base_class
        self.bitsize = bitsize


class Type:
    """
    Class representing a type in the context of an inferior process.
    """

    @property
    def name_identifier(self) -> str | None:
        """
        Returns the identifier of this type, eg:
        - someStructName
        - someEnumName
        - someTypedefName

        Returns None if the type is anonymous or does not have a name, such as:
        - Anonymous structs
        - Anonymous Typedefs
        - Basic types like char[], void, etc.
        """
        raise NotImplementedError()

    @property
    def name_to_human_readable(self) -> str:
        """
        Returns the human friendly name of this type, eg:
        - char [16]
        - int
        - char *
        - void *
        - fooStructName
        - barEnumName
        - barTypedefName

        This function is not standardized, may return different names in gdb/lldb, eg:
        gdb: `char [16]` or `char [50]` or `struct {...}`
        lldb: `char[16]` or `char[]`    or `(anonymous struct)`

        You should not use this function. Only for human eyes.
        """
        raise NotImplementedError()

    @property
    def sizeof(self) -> int:
        """
        The size of this type, in bytes.
        """
        raise NotImplementedError()

    @property
    def alignof(self) -> int:
        """
        The alignment of this type, in bytes.
        """
        raise NotImplementedError()

    @property
    def code(self) -> TypeCode:
        """
        What category of type this object belongs to.
        """
        raise NotImplementedError()

    def func_arguments(self) -> List[Type] | None:
        """
        Returns a list of function arguments type.

        Returns:
            List[Type] | None: The function arguments type, or None if debug information is missing.

        Raises:
            TypeError: If called on an unsupported type.
        """
        raise NotImplementedError()

    def fields(self) -> List[TypeField]:
        """
        List of all fields in this type, if it is a structured type.
        """
        raise NotImplementedError()

    def has_field(self, name: str) -> bool:
        """
        Whether this type has a field with the given name.
        """
        # This is a sensible default way to check for a field's existence.
        #
        # Implementations should, however, override this method if there's a
        # debugger-specific check for this that might be faster or more accurate.
        fields = self.fields()
        if fields:
            for field in fields:
                if field.name == name:
                    return True
        return False

    def array(self, count: int) -> Type:
        """
        Return a type that corresponds to an array whose elements have this type.
        """
        raise NotImplementedError()

    def pointer(self) -> Type:
        """
        Return a pointer type that has this type as its pointee.
        """
        raise NotImplementedError()

    def strip_typedefs(self) -> Type:
        """
        Return a type that corresponds to the base type after a typedef chain,
        if this is a typedef. Returns the type itself otherwise.
        """
        raise NotImplementedError()

    def target(self) -> Type:
        """
        Return the target of this reference type, if this is a reference type.
        """
        raise NotImplementedError()

    def keys(self) -> List[str]:
        """
        Returns a list containing all the field names of this type.
        """
        # Like with `has_fields`, we provide a sensible default implementation
        # based on `fields()`. Implementations are encouraged to override this
        # if there is a better debugger-specific way to do this.
        return [field.name for field in self.fields()]

    def enum_member(self, field_name: str) -> int | None:
        """
        Retrieve the integer value of an enum member.

        It returns:
        - integer value, when found field
        - returns None, If the field does not exist
        """
        if self.code != TypeCode.ENUM:
            raise TypeError("only enum supported")

        return next((f.enumval for f in self.fields() if f.name == field_name), None)

    def _offsetof(
        self, field_name: str, *, base_offset_bits: int = 0, nested_cyclic_types: List[Type] = None
    ) -> int | None:
        NESTED_TYPES = (TypeCode.STRUCT, TypeCode.UNION)
        struct_type = self
        if nested_cyclic_types is None:
            nested_cyclic_types = []

        if struct_type.code == TypeCode.TYPEDEF:
            struct_type = struct_type.strip_typedefs()

        if struct_type.code not in NESTED_TYPES:
            return None
        elif struct_type in nested_cyclic_types:
            return None

        # note: lldb.SBType and gdb.Type dont support Sets
        nested_cyclic_types.append(struct_type)

        for field in struct_type.fields():
            field_offset_bits = base_offset_bits + field.bitpos

            if field.name == field_name:
                if field_offset_bits % 8 != 0:
                    # Possible bit-fields, misaligned struct, or unexpected alignment
                    # This case is not supported because it introduces complexities
                    # in handling non-byte-aligned or bit-level field offsets
                    return None
                return field_offset_bits // 8

            nested_offset = field.type._offsetof(
                field_name,
                base_offset_bits=field_offset_bits,
                nested_cyclic_types=nested_cyclic_types,
            )
            if nested_offset is not None:
                return nested_offset

        return None

    def offsetof(self, field_name: str) -> int | None:
        """
        Calculate the byte offset of a field within a struct or union.

        This method recursively traverses nested structures and unions, and it computes the
        byte-aligned offset for the specified field.

        It returns:
        - offset in bytes if found
        - None if the field doesn't exist or if an unsupported alignment/bit-field is encountered
        """
        if self.code == TypeCode.POINTER:
            return self.target()._offsetof(field_name)
        return self._offsetof(field_name)

    def __eq__(self, rhs: object) -> bool:
        """
        Returns True if types are the same
        """
        raise NotImplementedError()


class Value:
    """
    Class representing a value in the context of an inferior process.
    """

    @property
    def address(self) -> Value | None:
        """
        The address of this value, in memory, if addressable, otherwise `None`.
        """
        raise NotImplementedError()

    # is_optimized_out is kind of a janky piece of API, honestly. It makes it
    # so that one's ability to call all other methods in this class is often
    # conditional on it being false, and it effectively splits the type into
    # two.
    #
    # There's only _one_ part of Pwndbg that uses it, and I really feel like we
    # should handle variables that have been optimized out some other way.
    #
    # TODO: Remove uses of is_optimized_out from plist and get rid of this.
    @property
    def is_optimized_out(self) -> bool:
        """
        Whether this value is present in debugging information, but has been
        optimized out of the actual program.
        """
        raise NotImplementedError()

    @property
    def type(self) -> Type:
        """
        The type associated with this value.
        """
        raise NotImplementedError()

    def dereference(self) -> Value:
        """
        If this is a poitner value, dereferences the pointer and returns a new
        instance of Value, containing the value pointed to by this pointer.
        """
        raise NotImplementedError()

    # The intent of this function has a great deal of overlap with that of
    # `pwndbg.aglib.memory.string()`. It probably makes sense to take this
    # functionality out of the debugger API.
    #
    # TODO: Move to single, common string function.
    def string(self) -> str:
        """
        If this value is a string, then this method converts it to a Python string.
        """
        raise NotImplementedError()

    def value_to_human_readable(self) -> str:
        """
        Converts a Value to a human-readable string representation.

        The format is similar to what is produced by the `str()` function for gdb.Value,
        displaying nested fields and pointers in a user-friendly way.

        **Usage Notes:**
        - This function is intended solely for displaying results to the user.
        - The output format may differ between debugger implementations (e.g., GDB vs LLDB),
          as each debugger may format values differently. For instance:
            - GDB might produce: '{\n  value = 0,\n  inner = {\n    next = 0x555555558098 <inner_a_node_b+8>\n  }\n}'
            - LLDB might produce: '(inner_a_node) *$PWNDBG_CREATED_VALUE_0 = {\n  value = 0\n  inner = {\n    next = 0x0000555555558098\n  }\n}'
        - As such, this function should not be relied upon for parsing or programmatic use.
        """
        raise NotImplementedError()

    # This is a GDB implementation detail.
    def fetch_lazy(self) -> None:
        """
        Fetches the value if it is lazy, does nothing otherwise.
        """
        raise NotImplementedError()

    def __int__(self) -> int:
        """
        Converts this value to an integer, if possible.
        """
        raise NotImplementedError()

    # Because casting is still sloppy (i.e. it accepts `gdb.Type` objects) in
    # some places, we have to allow `Any` here for lints to pass.
    #
    # TODO: Remove Any type from this function.
    def cast(self, type: Type | Any) -> Value:
        """
        Returns a new value with the same value as this object, but of the
        given type.
        """
        raise NotImplementedError()

    def __add__(self, rhs: int) -> Value:
        """
        Adds an integer to this value, if that makes sense. Throws an exception
        otherwise.
        """
        raise NotImplementedError()

    def __sub__(self, rhs: int) -> Value:
        """
        Subtract an integer from this value, if that makes sense. Throws an
        exception otherwise.
        """
        raise NotImplementedError()

    def __getitem__(self, idx: int | str) -> Value:
        """
        Gets the value with the given name that belongs to this value. For
        structure types, this is the field with the given name. For array types,
        this is the field at the given index. For pointer types, this is the
        value of `*(ptr+idx)`.
        """
        raise NotImplementedError()


class CommandHandle:
    """
    An opaque handle to an installed command.
    """

    def remove(self) -> None:
        """
        Removes this command from the command palette of the debugger.
        """
        raise NotImplementedError()


class EventType(Enum):
    """
    Events that can be listened for and reacted to in a debugger.

    The events types listed here are defined as follows:
        - `START`: This event is fired some time between the creation of or
          attachment to the process to be debugged, and the start of its
          execution.
        - `STOP`: This event is fired after execution of the process has been
          suspended, but before control is returned to the user for interactive
          debugging.
        - `EXIT`: This event is fired after the process being debugged has been
          detached from or has finished executing.
        - `MEMORY_CHANGED`: This event is fired when the user interactively makes
          changes to the memory of the process being debugged.
        - `REGISTER_CHANGED`: Like `MEMORY_CHANGED`, but for registers.
        - `CONTINUE`: This event is fired after the user has requested for
          process execution to continue after it had been previously suspended.
        - `NEW_MODULE`: This event is fired when a new application module has
          been encountered by the debugger. This usually happens when a new
          application module is loaded into the memory space of the process being
          debugged. In GDB terminology, these are called `objfile`s.
    """

    START = 0
    STOP = 1
    EXIT = 2
    MEMORY_CHANGED = 3
    REGISTER_CHANGED = 4
    CONTINUE = 5
    NEW_MODULE = 6


class Debugger:
    """
    The base class representing a debugger.
    """

    def setup(self, *args: Any) -> None:
        """
        Perform debugger-specific initialization.

        This method should be run immediately after `pwndbg.dbg` is set to an
        instance of this class, and, as such, is allowed to run code that
        depends on it being set.

        Because we can't really know what a given debugger object will need as
        part of its setup process, we allow for as many arguments as desired to
        be passed in, and leave it up to the implementations to decide what they
        need. This shouldn't be a problem, seeing as, unlike other methods in
        this class, this should only be called as part of the debugger-specific
        bringup code.
        """
        raise NotImplementedError()

    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        """
        The command history of the interactive session in this debugger.

        This function returns the last `last` items in the command history, as
        an oldest-to-youngest-sorted list of tuples, where the first element in
        each tuple is the index of the command in the history, and the second
        element is a string giving the command itself.
        """
        raise NotImplementedError()

    def lex_args(self, command_line: str) -> List[str]:
        """
        Lexes the given command line into a list of arguments, according to the
        conventions of the debugger being used and of the interactive session.
        """
        raise NotImplementedError()

    def selected_inferior(self) -> Process | None:
        """
        The inferior process currently being focused on in this interactive session.
        """
        raise NotImplementedError()

    def selected_thread(self) -> Thread | None:
        """
        The thread currently being focused on in this interactive session.
        """
        raise NotImplementedError()

    def selected_frame(self) -> Frame | None:
        """
        The stack frame currently being focused on in this interactive session.
        """
        raise NotImplementedError()

    def commands(self) -> List[str]:
        """
        List the commands available in this session.
        """
        raise NotImplementedError()

    def add_command(
        self, name: str, handler: Callable[[Debugger, str, bool], None], doc: str | None
    ) -> CommandHandle:
        """
        Adds a command with the given name to the debugger, that invokes the
        given function every time it is called.
        """
        raise NotImplementedError()

    def has_event_type(self, ty: EventType) -> bool:
        """
        Whether the given event type is supported by this debugger. Indicates
        that a user either can or cannot register an event handler of this type.
        """
        raise NotImplementedError()

    def event_handler(self, ty: EventType) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """
        Sets up the given function to be called when an event of the given type
        gets fired. Returns a callable that corresponds to the wrapped function.
        This function my be used as a decorator.
        """
        raise NotImplementedError()

    def suspend_events(self, ty: EventType) -> None:
        """
        Suspend delivery of all events of the given type until it is resumed
        through a call to `resume_events`.

        Events triggered during a suspension will be ignored, and will not be
        delived, even after delivery is resumed.
        """
        raise NotImplementedError()

    def resume_events(self, ty: EventType) -> None:
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

    def breakpoint_locations(self) -> List[BreakpointLocation]:
        """
        Returns a list of all breakpoint locations that are currently
        installed and enabled in the focused process.
        """
        raise NotImplementedError()

    # WARNING
    #
    # These are hacky parts of the API that were strictly necessary to bring up
    # pwndbg under LLDB without breaking it under GDB. Expect most of them to be
    # removed or replaced as the porting work continues.
    #

    def name(self) -> DebuggerType:
        """
        The type of the current debugger.
        """
        raise NotImplementedError()

    # We'd like to be able to gate some imports off during porting. This aids in
    # that.
    def is_gdblib_available(self) -> bool:
        """
        Whether gdblib is available under this debugger.
        """
        raise NotImplementedError()

    def string_limit(self) -> int:
        """
        The maximum size of a string.
        """
        raise NotImplementedError()

    def addrsz(self, address: Any) -> str:
        """
        Format the given address value.
        """
        raise NotImplementedError()

    def get_cmd_window_size(self) -> Tuple[int, int]:
        """
        The size of the command window, in characters, if available.
        """
        raise NotImplementedError()

    @property
    def pre_ctx_lines(self) -> int:
        """
        Our prediction on how many lines of text will be printed as
        a preamble (right after the prompt, and before the context)
        the next time the context is printed.

        This includes any lines the underlying debugger generates.

        The user never sees these lines when context-clear-screen
        is enabled.
        """
        raise NotImplementedError()

    def set_python_diagnostics(self, enabled: bool) -> None:
        """
        Enables or disables Python diagnostic messages for this debugger.
        """
        raise NotImplementedError()
