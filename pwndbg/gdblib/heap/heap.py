from __future__ import annotations

from typing import Any

import gdb


class MemoryAllocator:
    """Heap abstraction layer."""

    def breakpoint(self, event: str) -> gdb.Breakpoint:
        """Enables breakpoints on the specific event.

        Arguments:
            event(str): One of 'alloc','realloc','free'

        Returns:
            A gdb.Breakpoint object.
        """
        raise NotImplementedError()

    def summarize(self, address: int, **kwargs: Any) -> str:
        """Returns a textual summary of the specified address.

        Arguments:
            address(int): Address of the heap block to summarize.

        Returns:
            A string.
        """
        raise NotImplementedError()

    def containing(self, address: int) -> int:
        """Returns the address of the allocation which contains 'address'.

        Arguments:
            address(int): Address to look up.

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
