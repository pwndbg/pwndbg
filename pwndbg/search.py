"""
Search the address space for byte patterns.
"""

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap


def search(searchfor, mappings=None, start=None, end=None, executable=False, writable=False):
    """Search inferior memory for a byte sequence.

    Arguments:
        searchfor(bytes): Byte sequence to find
        mappings(list): List of pwndbg.lib.memory.Page objects to search
            By default, uses all available mappings.
        start(int): First address to search, inclusive.
        end(int): Last address to search, exclusive.
        executable(bool): Restrict search to executable pages
        writable(bool): Restrict search to writable pages

    Yields:
        An iterator on the address matches
    """
    i = gdb.selected_inferior()

    maps = mappings or pwndbg.gdblib.vmmap.get()

    if end and start:
        assert start < end, "Last address to search must be greater then first address"
        maps = [m for m in maps if start in m or (end - 1) in m]
    elif start:
        maps = [m for m in maps if start in m]
    elif end:
        maps = [m for m in maps if (end - 1) in m]

    if executable:
        maps = [m for m in maps if m.execute]

    if writable:
        maps = [m for m in maps if m.write]

    for vmmap in maps:
        start = vmmap.start
        end = vmmap.end

        while True:
            # No point in searching if we can't read the memory
            if not pwndbg.gdblib.memory.peek(start):
                break

            length = end - start
            if length <= 0:
                break

            start = i.search_memory(start, length, searchfor)

            if start is None:
                break

            # Fix bug: In kernel mode, search_memory may return a negative address,
            # e.g. -1073733344, which supposed to be 0xffffffffc0002120 in kernel.
            start &= 0xFFFFFFFFFFFFFFFF

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            if not pwndbg.gdblib.memory.peek(start):
                break

            yield start
            start += len(searchfor)
