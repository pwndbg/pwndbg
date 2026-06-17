"""
Reading, writing, and describing memory.
"""

from __future__ import annotations

import os
from os.path import relpath

import pwndbg

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


def format_address(
    vaddr: int, memsz: int, permstr: str, offset: int, ptrsize: int, objfile: str | None = None
) -> str:
    "Format the given address as a string."

    width = 2 + 2 * ptrsize
    if memsz > 0x100000000:
        return f"{vaddr:#{width}x} {vaddr + memsz:#{width}x} {permstr} {memsz:8x} {offset:6x} {objfile or ''}"

    return f"{vaddr:#{width}x} {vaddr + memsz:#{width}x} {permstr} {memsz:8x} {offset:7x} {objfile or ''}"


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

    """
    consts
    """
    R_OK = os.R_OK
    W_OK = os.W_OK
    X_OK = os.X_OK

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

    in_darwin_shared_cache: bool
    """
    Whether this mapping is part of the Darwin Shared Cache.

    This is an interesting property to know, as these entries may not be useful
    to us at all times, and having an easy way to filter them out is helpful..
    """

    def __init__(
        self,
        start: int,
        size: int,
        flags: int,
        offset: int,
        arch_ptrsize: int,
        objfile: str = "",
        in_darwin_shared_cache: bool = False,
        protection_key: int | None = None,
        vm_flags: list[str] | None = None,
    ) -> None:
        self.vaddr = start
        self.memsz = size
        self.flags = flags
        self.offset = offset
        self.objfile = objfile
        self.in_darwin_shared_cache = in_darwin_shared_cache
        self.arch_ptrsize = arch_ptrsize
        self.protection_key = protection_key
        self.vm_flags = vm_flags

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
    def is_heap(self) -> bool:
        return self.objfile.startswith("[heap")

    @property
    def is_memory_mapped_file(self) -> bool:
        """Whether this mapping is backed by a named file on disk.

        Returns True when ``objfile`` is a real filesystem path (e.g.
        ``/usr/lib/libc.so.6``).  Returns False for kernel-virtual regions
        whose names are wrapped in square brackets — ``[stack]``, ``[heap]``,
        ``[vdso]``, ``[anon_shmem]``, etc. — because those are not files that
        can be opened or parsed as ELF objects.
        """
        return len(self.objfile) != 0 and self.objfile[0] != "["

    @property
    def read(self) -> bool:
        return bool(self.flags & self.R_OK)

    @property
    def write(self) -> bool:
        return bool(self.flags & self.W_OK)

    @property
    def execute(self) -> bool:
        return bool(self.flags & self.X_OK)

    @property
    def ro(self) -> bool:
        return self.read and not (self.write or self.execute)

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
                "r" if flags & self.R_OK else "-",
                "w" if flags & self.W_OK else "-",
                "x" if flags & self.X_OK else "-",
                "p",
            ]
        )

    def __str__(self) -> str:
        if pwndbg.config.vmmap_prefer_relpaths and self.objfile:
            rel = relpath(self.objfile)
            # Keep the origin path when relative paths are longer than absolute ones.
            objfile = self.objfile if len(rel) > len(self.objfile) else rel
        else:
            objfile = self.objfile

        return format_address(
            self.vaddr, self.memsz, self.permstr, self.offset, self.arch_ptrsize, objfile=objfile
        )

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
