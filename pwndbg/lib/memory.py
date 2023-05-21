"""
Reading, writing, and describing memory.
"""

import os

import pwndbg.gdblib.arch

PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE - 1)


def round_down(address: int, align: int) -> int:
    """round_down(address, align) -> int

    Round down ``address`` to the nearest increment of ``align``.
    """
    return address & ~(align - 1)


def round_up(address: int, align: int) -> int:
    """round_up(address, align) -> int

    Round up ``address`` to the nearest increment of ``align``.
    """
    return (address + (align - 1)) & (~(align - 1))


align_down = round_down
align_up = round_up


def page_align(address: int) -> int:
    """page_align(address) -> int

    Round down ``address`` to the nearest page boundary.
    """
    return round_down(address, PAGE_SIZE)


def page_size_align(address: int) -> int:
    return round_up(address, PAGE_SIZE)


def page_offset(address: int) -> int:
    return address & (PAGE_SIZE - 1)


# TODO: Move to a test
assert round_down(0xDEADBEEF, 0x1000) == 0xDEADB000
assert round_up(0xDEADBEEF, 0x1000) == 0xDEADC000


class Page:
    """
    Represents the address space and page permissions of at least
    one page of memory.
    """

    __slots__ = ("start", "end", "size", "flags", "offset", "objfile")

    def __init__(self, start: int, size: int, flags: int, offset: int, objfile: str = "") -> None:
        # Mapping start address
        self.start = start
        # Address beyond mapping - the last effective address is self.end-1
        # It is the same as displayed in /proc/<pid>/maps
        self.end = start + size

        self.size = size
        self.flags = flags
        self.offset = offset
        self.objfile = objfile

    @property
    def is_stack(self) -> bool:
        return self.objfile == "[stack]"

    @property
    def is_memory_mapped_file(self) -> bool:
        return len(self.objfile) != 0 and self.objfile[0] != "[" and self.objfile != "<pt>"

    @property
    def read(self) -> bool:
        return bool(self.flags & os.R_OK)

    @property
    def write(self) -> bool:
        return bool(self.flags & os.W_OK)

    @property
    def execute(self) -> bool:
        return bool(self.flags & os.X_OK)

    @property
    def rw(self) -> bool:
        return self.read and self.write

    @property
    def rwx(self) -> bool:
        return self.read and self.write and self.execute

    @property
    def permstr(self) -> str:
        flags = self.flags
        return "".join(
            [
                "r" if flags & os.R_OK else "-",
                "w" if flags & os.W_OK else "-",
                "x" if flags & os.X_OK else "-",
                "p",
            ]
        )

    def __str__(self) -> str:
        return "{start:#{width}x} {end:#{width}x} {permstr} {size:8x} {offset:6x} {objfile}".format(
            start=self.start,
            end=self.end,
            permstr=self.permstr,
            size=self.size,
            offset=self.offset,
            objfile=self.objfile or "",
            width=2 + 2 * pwndbg.gdblib.arch.ptrsize,
        )

    def __repr__(self) -> str:
        return "%s(%r)" % (self.__class__.__name__, self.__str__())

    def __contains__(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __eq__(self, other) -> bool:
        return self.start == other.start

    def __lt__(self, other) -> bool:
        return self.start < other.start

    def __hash__(self):
        return hash((self.start, self.end, self.size, self.flags, self.offset, self.objfile))
