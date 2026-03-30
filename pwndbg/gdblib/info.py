"""
Runs a few useful commands which are available under "info".
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import NamedTuple

import gdb

import pwndbg.lib.cache

# TODO: Add symbol, threads, dll, program


@pwndbg.lib.cache.cache_until("exit")
def proc_mappings() -> str:
    try:
        return gdb.execute("info proc mappings", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.cache.cache_until("exit")
def auxv() -> str:
    try:
        return gdb.execute("info auxv", to_string=True)
    except gdb.error:
        return ""


@pwndbg.lib.cache.cache_until("stop")
def files() -> str:
    try:
        return gdb.execute("info files", to_string=True)
    except gdb.error:
        return ""


class Section(NamedTuple):
    objfile: str
    section: str
    start: int
    size: int
    offset: int


def iter_sections() -> Iterator[Section]:
    """
    Parse sections from GDB `maintenance info target-sections`.

    Example output:
    From '/bin/nginx', file type elf64-x86-64:
     [0]      0x00000350->0x00000390 at 0x00000350: .note.gnu.property ALLOC LOAD READONLY DATA HAS_CONTENTS
              Start: 0x558fb29f4350, End: 0x558fb29f4390, Owner token: 0xaaaad5b30c50
     [1]      0x00000390->0x000003b4 at 0x00000390: .note.gnu.build-id ALLOC LOAD READONLY DATA HAS_CONTENTS
              Start: 0x558fb29f4390, End: 0x558fb29f43b4, Owner token: 0xaaaad5b30c50
    """

    # Workaround for GDB bug:
    # Without executing this command first, `maintenance info target-sections`
    # may return incomplete or missing section info. (When using with core-files)
    gdb.execute("info sharedlibrary", to_string=True)

    lines = gdb.execute("maintenance info target-sections", to_string=True)
    current_file = None
    current_section_offset = None
    current_section_name = None

    for line in lines.splitlines():
        line = line.strip()

        # From '/bin/nginx', file type elf64-x86-64:
        if line.startswith("From '"):
            current_file = line[6:].rsplit("'", maxsplit=1)[0]
            continue

        # [0]      0x00000350->0x00000390 at 0x00000350: .note.gnu.property ALLOC LOAD READONLY DATA HAS_CONTENTS
        if line.startswith("["):
            left, right = line.split(": ", maxsplit=1)
            current_section_offset = int(left.split(" at ", maxsplit=1)[1], 16)
            current_section_name = right.split(" ", maxsplit=1)[0]
            continue

        # Start: 0x558fb29f4350, End: 0x558fb29f4390, Owner token: 0xaaaad5b30c50
        if line.startswith("Start:"):
            _, start, _, end, *_ = line.replace(",", "").split(" ")
            start, end = int(start, 16), int(end, 16)

            yield Section(
                objfile=current_file,
                section=current_section_name,
                start=start,
                size=end - start,
                offset=current_section_offset,
            )


@pwndbg.lib.cache.cache_until("stop", "objfile")
def sections() -> tuple[Section, ...]:
    return tuple(iter_sections())
