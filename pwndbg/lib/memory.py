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

    vaddr = 0  #: Starting virtual address
    memsz = 0  #: Size of the address space, in bytes
    flags = 0  #: Flags set by the ELF file, see PF_X, PF_R, PF_W
    offset = 0  #: Offset into the original ELF file that the data is loaded from
    objfile = ""  #: Path to the ELF on disk

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
    def is_stack(self):
        return self.objfile == "[stack]"

    @property
    def is_memory_mapped_file(self):
        return len(self.objfile) > 0 and self.objfile[0] != "[" and self.objfile != "<pt>"

    @property
    def read(self) -> bool:
        return bool(self.flags & 4)

    @property
    def write(self) -> bool:
        return bool(self.flags & 2)

    @property
    def execute(self) -> bool:
        return bool(self.flags & 1)

    @property
    def rw(self):
        return self.read and self.write

    @property
    def rwx(self) -> bool:
        return self.read and self.write and self.execute

    @property
    def permstr(self):
        flags = self.flags
        return "".join(
            [
                "r" if flags & os.R_OK else "-",
                "w" if flags & os.W_OK else "-",
                "x" if flags & os.X_OK else "-",
                "p",
            ]
        )

    def __str__(self):
        return "{start:#{width}x} {end:#{width}x} {permstr} {size:8x} {offset:6x} {objfile}".format(
            start=self.vaddr,
            end=self.vaddr + self.memsz,
            permstr=self.permstr,
            size=self.memsz,
            offset=self.offset,
            objfile=self.objfile or "",
            width=2 + 2 * pwndbg.gdblib.arch.ptrsize,
        )

    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.__str__())

    def __contains__(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __eq__(self, other) -> bool:
        return self.vaddr == getattr(other, "vaddr", other)

    def __lt__(self, other) -> bool:
        return self.vaddr < getattr(other, "vaddr", other)

    def __hash__(self):
        return hash((self.vaddr, self.memsz, self.flags, self.offset, self.objfile))
