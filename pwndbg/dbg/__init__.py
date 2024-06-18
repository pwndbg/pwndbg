"""
The abstracted debugger interface.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from typing import List
from typing import Tuple

dbg: Debugger = None


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

    # This is a GDB imeplementation detail.
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

    # Because casting is still sloppy (i.e. it acceps `gdb.Type` objects) in
    # some places, we have to allow it here for lints to pass.
    #
    # TODO: Remove Any type from this function.
    def cast(self, type: Type | Any) -> Value:
        """
        Returns a new value with the same value as this object, but of the
        given type.
        """
        raise NotImplementedError()


class Debugger:
    """
    The base class
    """

    def setup(self, *args: Any) -> None:
        """
        Perform debugger-specific initialization.

        Because we can't really know what a given debugger object will need as
        part of its setup process, we allow for as many arguments as desired to
        be passed in, and leave it up to the implementations to decide what they
        need.

        This shouldn't be a problem, seeing as, unlike other methods in this
        class, this should only be called as part of the debugger-specific
        bringup code.
        """
        raise NotImplementedError()

    # WARNING
    #
    # These are hacky parts of the API that were strictly necessary to bring up
    # pwndbg under LLDB without breaking it under GDB. Expect most of them to be
    # removed or replaced as the porting work continues.
    #

    # This function will be split up into a frame-context and a global-context
    # versions very soon, in a way that properly represents the way evaluation
    # works under both GDB and LLDB.
    #
    # TODO: Split up `evaluate_expressions` into its global and local versions.
    def evaluate_expression(self, expression: str) -> Value:
        """
        Evaluate the given expression in the context of the current frame, and
        return a `Value`.
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
