"""
Reading, writing, and describing memory.
"""

from __future__ import annotations

import os
from os.path import relpath

import pwndbg.aglib.arch

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


class Page:
    """
    Represents the address space and page permissions of at least
    one page of memory.
    """

    vaddr = 0  #: Starting virtual address
    memsz = 0  #: Size of the address space, in bytes
    flags = 0  #: Flags set by the ELF file, see PF_X, PF_R, PF_W
    offset = 0  #: Offset into the original ELF file that the data is loaded from
    objfile = ""  #: Path to the ELF on disk
    """
    Possible non-empty values of `objfile`:
    - Contains square brackets "[]" if it's not a memory mapped file.
        Examples: [stack], [vsyscall], [heap], [vdso]
    - A path to a file, such as `/usr/lib/libc.so.6`
    """

    def __init__(self, start: int, size: int, flags: int, offset: int, objfile: str = "") -> None:
        self.vaddr = start
        self.memsz = size
        self.flags = flags
        self.offset = offset
        self.objfile = objfile

        # if self.rwx:
        # self.flags = self.flags ^ 1

    @property
    def start(self) -> int:
        """
        Mapping start address.
        """
        return self.vaddr

    @property
    def end(self) -> int:
        """
        Address beyond mapping. So the last effective address is self.end-1
        It is the same as displayed in /proc/<pid>/maps
        """
        return self.vaddr + self.memsz

    @property
    def is_stack(self) -> bool:
        return self.objfile.startswith("[stack")

    @property
    def is_memory_mapped_file(self) -> bool:
        return len(self.objfile) != 0 and self.objfile[0] != "["

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
    def wx(self) -> bool:
        return self.write and self.execute

    @property
    def rwx(self) -> bool:
        return self.read and self.write and self.execute

    @property
    def is_guard(self) -> bool:
        return not (self.read or self.write or self.execute)

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
        if pwndbg.config.vmmap_prefer_relpaths:
            rel = relpath(self.objfile)
            # Keep the origin path when relative paths are longer than absolute ones.
            objfile = self.objfile if len(rel) > len(self.objfile) else rel
        else:
            objfile = self.objfile
        width = 2 + 2 * pwndbg.aglib.arch.ptrsize
        return f"{self.vaddr:#{width}x} {self.vaddr + self.memsz:#{width}x} {self.permstr} {self.memsz:8x} {self.offset:6x} {objfile or ''}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__str__()!r})"

    def __contains__(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __eq__(self, other: object) -> bool:
        return self.vaddr == getattr(other, "vaddr", other)

    def __lt__(self, other: object) -> bool:
        return self.vaddr < getattr(other, "vaddr", other)  # type: ignore[arg-type]

    def __hash__(self) -> int:
        return hash((self.vaddr, self.memsz, self.flags, self.offset, self.objfile))
