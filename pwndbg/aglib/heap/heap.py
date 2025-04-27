from __future__ import annotations

from typing import Any


class MemoryAllocator:
    """Heap abstraction layer."""

    # This function isn't actually implemented anywhere. It originally returned
    # `gdb.Breakpoint`, but, in order to facilitate the port to aglib, that
    # type association was removed. It should be put back as soon as the
    # Debugger-agnostic API gains the ability to set breakpoints.
    #
    # TODO: Change `Any` to the Debugger-agnostic breakpoint type when it gets created

    def summarize(self, address: int, **kwargs: Any) -> str:
        """Returns a textual summary of the specified address.

        Arguments:
            address: Address of the heap block to summarize.

        Returns:
            A string.
        """
        raise NotImplementedError()

    def containing(self, address: int) -> int:
        """Returns the address of the allocation which contains 'address'.

        Arguments:
            address: Address to look up.

        Returns:
            An integer.
        """
        raise NotImplementedError()

    def is_initialized(self) -> bool:
        """Returns whether the allocator is initialized or not.

        Returns:
            A boolean.
        """
        raise NotImplementedError()

    def libc_has_debug_syms(self) -> bool:
        """Returns whether the libc has debug symbols or not.

        Returns:
            A boolean.
        """
        raise NotImplementedError()
