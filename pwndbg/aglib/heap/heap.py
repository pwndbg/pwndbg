from __future__ import annotations

import pwndbg.lib.memory


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

    def get_sbrk_heap_region(self) -> pwndbg.lib.memory.Page | None:
        """Returns the sbrk heap region.

        Returns:
            A Page object or None.
        """
        raise NotImplementedError()
