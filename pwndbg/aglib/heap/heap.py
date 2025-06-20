from __future__ import annotations


class MemoryAllocator:
    """Heap abstraction layer."""

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
