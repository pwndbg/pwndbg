"""
Reading, writing, and describing memory.
"""


import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.qemu
import pwndbg.gdblib.typeinfo
from pwndbg.lib.memory import PAGE_MASK
from pwndbg.lib.memory import PAGE_SIZE

MMAP_MIN_ADDR = 0x8000


def read(addr, count, partial=False):
    """read(addr, count, partial=False) -> bytearray

    Read memory from the program being debugged.

    Arguments:
        addr(int): Address to read
        count(int): Number of bytes to read
        partial(bool): Whether less than ``count`` bytes can be returned

    Returns:
        :class:`bytearray`: The memory at the specified address,
        or ``None``.
    """
    result = b""
    count = max(int(count), 0)

    try:
        result = gdb.selected_inferior().read_memory(addr, count)
    except gdb.error as e:
        if not partial:
            raise

        if not hasattr(e, "message"):
            e.message = str(e)

        stop_addr = int(e.message.split()[-1], 0)
        if stop_addr != addr:
            return read(addr, stop_addr - addr)

        # QEMU will return the start address as the failed
        # read address.  Try moving back a few pages at a time.
        stop_addr = addr + count

        # Move the stop address down to the previous page boundary
        stop_addr &= PAGE_MASK
        while stop_addr > addr:
            result = read(addr, stop_addr - addr)

            if result:
                return result

            # Move down by another page
            stop_addr -= PAGE_SIZE

    return bytearray(result)


def readtype(gdb_type, addr):
    """readtype(gdb_type, addr) -> int

    Reads an integer-type (e.g. ``uint64``) and returns a Python
    native integer representation of the same.

    Arguments:
        gdb_type(gdb.Type): GDB type to read
        addr(int): Address at which the value to be read resides

    Returns:
        :class:`int`
    """
    return int(gdb.Value(addr).cast(gdb_type.pointer()).dereference())


def write(addr, data):
    """write(addr, data)

    Writes data into the memory of the process being debugged.

    Arguments:
        addr(int): Address to write
        data(str,bytes,bytearray): Data to write
    """
    if isinstance(data, str):
        data = bytes(data, "utf8")

    # Throws an exception if can't access memory
    gdb.selected_inferior().write_memory(addr, data)


def peek(address):
    """peek(address) -> str

    Read one byte from the specified address.

    Arguments:
        address(int): Address to read

    Returns:
        :class:`str`: A single byte of data, or ``None`` if the
        address cannot be read.
    """
    try:
        return read(address, 1)
    except Exception:
        pass
    return None


def poke(address):
    """poke(address)

    Checks whether an address is writable.

    Arguments:
        address(int): Address to check

    Returns:
        :class:`bool`: Whether the address is writable.
    """
    c = peek(address)
    if c is None:
        return False
    try:
        write(address, c)
    except Exception:
        return False
    return True


def string(addr, max=4096):
    """Reads a null-terminated string from memory.

    Arguments:
        addr(int): Address to read from
        max(int): Maximum string length (default 4096)

    Returns:
        An empty bytearray, or a NULL-terminated bytearray.
    """
    if peek(addr):
        data = bytearray(read(addr, max, partial=True))

        try:
            return data[: data.index(b"\x00")]
        except ValueError:
            pass

    return bytearray()


def byte(addr):
    """byte(addr) -> int

    Read one byte at the specified address
    """
    return readtype(pwndbg.gdblib.typeinfo.uchar, addr)


def uchar(addr):
    """uchar(addr) -> int

    Read one ``unsigned char`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uchar, addr)


def ushort(addr):
    """ushort(addr) -> int

    Read one ``unisgned short`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.ushort, addr)


def uint(addr):
    """uint(addr) -> int

    Read one ``unsigned int`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint, addr)


def pvoid(addr):
    """pvoid(addr) -> int

    Read one pointer from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.pvoid, addr)


def u8(addr):
    """u8(addr) -> int

    Read one ``uint8_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint8, addr)


def u16(addr):
    """u16(addr) -> int

    Read one ``uint16_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint16, addr)


def u32(addr):
    """u32(addr) -> int

    Read one ``uint32_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint32, addr)


def u64(addr):
    """u64(addr) -> int

    Read one ``uint64_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint64, addr)


def u(addr, size=None):
    """u(addr, size=None) -> int

    Read one ``unsigned`` integer from the specified address,
    with the bit-width specified by ``size``, which defaults
    to the pointer width.
    """
    if size is None:
        size = pwndbg.gdblib.arch.ptrsize * 8
    return {8: u8, 16: u16, 32: u32, 64: u64}[size](addr)


def s8(addr):
    """s8(addr) -> int

    Read one ``int8_t`` from the specified address
    """
    return readtype(pwndbg.gdblib.typeinfo.int8, addr)


def s16(addr):
    """s16(addr) -> int

    Read one ``int16_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int16, addr)


def s32(addr):
    """s32(addr) -> int

    Read one ``int32_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int32, addr)


def s64(addr):
    """s64(addr) -> int

    Read one ``int64_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int64, addr)


# TODO: `readtype` is just `int(poi(type, addr))`
def poi(type, addr):
    """poi(addr) -> gdb.Value

    Read one ``gdb.Type`` object at the specified address.
    """
    return gdb.Value(addr).cast(type.pointer()).dereference()


@pwndbg.lib.memoize.reset_on_stop
def find_upper_boundary(addr, max_pages=1024):
    """find_upper_boundary(addr, max_pages=1024) -> int

    Brute-force search the upper boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.lib.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.gdblib.memory.read(addr, 1)
            # import sys
            # sys.stdout.write(hex(addr) + '\n')
            addr += PAGE_SIZE

            # Sanity check in case a custom GDB server/stub
            # incorrectly returns a result from read
            # (this is most likely redundant, but its ok to keep it?)
            if addr > pwndbg.gdblib.arch.ptrmask:
                return pwndbg.gdblib.arch.ptrmask
    except gdb.MemoryError:
        pass
    return addr


@pwndbg.lib.memoize.reset_on_stop
def find_lower_boundary(addr, max_pages=1024):
    """find_lower_boundary(addr, max_pages=1024) -> int

    Brute-force search the lower boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.lib.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.gdblib.memory.read(addr, 1)
            addr -= PAGE_SIZE

            # Sanity check (see comment in find_upper_boundary)
            if addr < 0:
                return 0

    except gdb.MemoryError:
        addr += PAGE_SIZE
    return addr


@pwndbg.gdblib.events.start
def update_min_addr():
    global MMAP_MIN_ADDR
    if pwndbg.gdblib.qemu.is_qemu_kernel():
        MMAP_MIN_ADDR = 0
