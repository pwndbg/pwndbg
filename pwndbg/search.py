"""
Search the address space for byte patterns.
"""

from __future__ import annotations

from typing import Collection
from typing import Generator

import pwndbg.aglib.vmmap


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
        searchfor: Byte sequence to find
        mappings: List of pwndbg.lib.memory.Page objects to search
            By default, uses all available mappings.
        start: First address to search, inclusive.
        end: Last address to search, exclusive.
        step: Size of memory region to skip each result
        aligned: Strict byte alignment for search result
        limit: Maximum number of results to return
        executable: Restrict search to executable pages
        writable: Restrict search to writable pages

    Yields:
        An iterator on the address matches
    """
    i = pwndbg.dbg.selected_inferior()

    maps = mappings or pwndbg.aglib.vmmap.get()

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

    count = 0
    if limit and limit <= 0:
        return

    for vmmap in maps:
        start = vmmap.start
        end = vmmap.end

        if limit and count >= limit:
            break

        for element in i.find_in_memory(
            bytearray(searchfor),
            start,
            end - start,
            aligned or 1,
            (limit - count) if limit else -1,
            step or -1,
        ):
            yield element
            count += 1
