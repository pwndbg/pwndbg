"""
Search the address space for byte patterns.
"""

from __future__ import annotations

from typing import Collection
from typing import Generator

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap


def search(
    searchfor: bytes,
    mappings: Collection[pwndbg.lib.memory.Page] | None = None,
    start: int | None = None,
    end: int | None = None,
    step: int | None = None,
    aligned: int | None = None,
    limit: int | None = None,
    executable: bool = False,
    writable: bool = False,
) -> Generator[int, None, None]:
    """Search inferior memory for a byte sequence.

    Arguments:
        searchfor(bytes): Byte sequence to find
        mappings(list): List of pwndbg.lib.memory.Page objects to search
            By default, uses all available mappings.
        start(int): First address to search, inclusive.
        end(int): Last address to search, exclusive.
        step(int): Size of memory region to skip each result
        aligned(int): Strict byte alignment for search result
        limit(int): Maximum number of results to return
        executable(bool): Restrict search to executable pages
        writable(bool): Restrict search to writable pages

    Yields:
        An iterator on the address matches
    """
    i = gdb.selected_inferior()

    maps = mappings or pwndbg.gdblib.vmmap.get()
    found_count = 0

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

    if len(maps) == 0:
        print("No applicable memory regions found to search in.")
        return

    for vmmap in maps:
        start = vmmap.start
        end = vmmap.end

        if limit and found_count >= limit:
            break

        while True:
            # No point in searching if we can't read the memory
            if not pwndbg.gdblib.memory.peek(start):
                break

            length = end - start
            if length <= 0:
                break

            try:
                start = i.search_memory(start, length, searchfor)
            except gdb.error as e:
                # While remote debugging on an embedded device and searching
                # through a large memory region (~512mb), gdb may return an error similar
                # to `error: Invalid hex digit 116`, even though the search
                # itself is ok. It seems to have to do with a timeout.
                print(f"WARN: gdb.search_memory failed with: {e}")
                if e.args[0].startswith("Invalid hex digit"):
                    print(
                        "WARN: This is possibly related to a timeout. Connection is likely broken."
                    )
                    break
                start = None
                pass

            if start is None:
                break

            # Fix bug: In kernel mode, search_memory may return a negative address,
            # e.g. -1073733344, which supposed to be 0xffffffffc0002120 in kernel.
            start &= 0xFFFFFFFFFFFFFFFF

            # Ignore results that don't match required alignment
            if aligned and start & (aligned - 1):
                start = pwndbg.lib.memory.round_up(start, aligned)
                continue

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            if not pwndbg.gdblib.memory.peek(start):
                break

            yield start
            found_count += 1
            if limit and found_count >= limit:
                break

            if step is not None:
                start = pwndbg.lib.memory.round_down(start, step) + step
            else:
                if aligned:
                    start = pwndbg.lib.memory.round_up(start + len(searchfor), aligned)
                else:
                    start += len(searchfor)
