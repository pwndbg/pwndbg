"""
The abstracted debugger interface.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from typing import Callable
from typing import List
from typing import Literal
from typing import Sequence
from typing import Tuple
from typing import TypeVar

import pwndbg.lib.memory

dbg: Debugger = None

T = TypeVar("T")


class Error(Exception):
    pass


class Arch:
    """
    The definition of an architecture.
    """

    @property
    def endian(self) -> Literal["little", "big"]:
        """
        Wether code in this module is little or big.
        """
        raise NotImplementedError()

    @property
    def name(self) -> str:
        """
        Name of the architecture.
        """
        raise NotImplementedError()

    @property
    def ptrsize(self) -> int:
        """
        Length of the pointer in this module.
        """
        raise NotImplementedError()


class Registers:
    """
    A handle to the register values in a frame.
    """

    def by_name(self, name: str) -> Value | None:
        """
        Gets the value of a register if it exists, None otherwise.
        """
        raise NotImplementedError()


class Frame:
    def evaluate_expression(self, expression: str) -> Value:
        """
        Evaluate the given expression in the context of this frame, and
        return a `Value`.
        """
        raise NotImplementedError()

    def regs(self) -> Registers:
        """
        Access the values of the registers in this frame.
        """
        raise NotImplementedError()


class Thread:
    def bottom_frame(self) -> Frame:
        """
        Frame at the bottom of the call stack for this thread.
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

    def has_reliable_perms(self) -> bool:
        """
        Returns whether the permissions in this memory map are reliable.
        """
        raise NotImplementedError()

    def ranges(self) -> Sequence[pwndbg.lib.memory.Page]:
        """
        Returns all ranges in this memory map.
        """
        raise NotImplementedError()


class Process:
    def threads(self) -> List[Thread]:
        """
        Returns a list containing the threads in this process.
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

    # We'll likely have to expand this into a Symbol class and change this to a
    # `symbol_at_address` function later on.
    def symbol_name_at_address(self, address: int) -> str | None:
        """
        Returns the name of the symbol at the given address in the program, if
        one exists.
        """
        raise NotImplementedError()

    def arch(self) -> Arch:
        """
        The default architecture of this process.
        """
        raise NotImplementedError()


class TypeCode(Enum):
    """
    Broad categories of types.
    """

    POINTER = 1
    ARRAY = 2
    STRUCT = 3
    TYPEDEF = 4
    UNION = 5
    INT = 6
    ENUM = 7


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

    def fields(self) -> List[TypeField] | None:
        """
        List of all fields in this type, if it is a structured type.
        """
        raise NotImplementedError()

    def array(self, count: int) -> Type:
        """
        Return a type that corresponds to an array whole elements have this type.
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
    # `pwndbg.gdblib.memory.string()`. It probably makes sense to take this
    # functionality out of the debugger API.
    #
    # TODO: Move to single, common string function.
    def string(self) -> str:
        """
        If this value is a string, then this method converts it to a Python string.
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

    # WARNING
    #
    # These are hacky parts of the API that were strictly necessary to bring up
    # pwndbg under LLDB without breaking it under GDB. Expect most of them to be
    # removed or replaced as the porting work continues.
    #

    # We'd like to be able to gate some imports off during porting. This aids in
    # that.
    def is_gdblib_available(self) -> bool:
        """
        Whether gdblib is available under this debugger.
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

    def set_python_diagnostics(self, enabled: bool) -> None:
        """
        Enables or disables Python diagnostic messages for this debugger.
        """
        raise NotImplementedError()
