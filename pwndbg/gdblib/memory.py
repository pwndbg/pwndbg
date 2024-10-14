"""
Reading, writing, and describing memory.
"""

from __future__ import annotations

import re
from typing import Dict
from typing import Set
from typing import Union

import gdb

import pwndbg.aglib.arch
import pwndbg.gdblib.qemu
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.lib.memory import PAGE_MASK
from pwndbg.lib.memory import PAGE_SIZE

GdbDict = Dict[str, Union["GdbDict", int]]


MMAP_MIN_ADDR = 0x8000


def read(addr: int, count: int, partial: bool = False) -> bytearray:
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

        message = str(e)

        stop_addr = addr
        match = re.search(r"Memory at address (\w+) unavailable\.", message)
        if match:
            stop_addr = int(match.group(1), 0)
        else:
            stop_addr = int(message.split()[-1], 0)

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


def readtype(gdb_type: gdb.Type, addr: int) -> int:
    """readtype(gdb_type, addr) -> int

    Reads an integer-type (e.g. ``uint64``) and returns a Python
    native integer representation of the same.

    Arguments:
        gdb_type(gdb.Type): GDB type to read
        addr(int): Address at which the value to be read resides

    Returns:
        :class:`int`
    """
    return int(get_typed_pointer_value(gdb_type, addr))


def write(addr: int, data: str | bytes | bytearray) -> None:
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


def peek(address: int) -> bytearray | None:
    """peek(address) -> bytearray

    Read one byte from the specified address.

    Arguments:
        address(int): Address to read

    Returns:
        :class:`bytearray`: A single byte of data, or ``None`` if the
        address cannot be read.
    """
    try:
        return read(address, 1)
    except gdb.MemoryError:
        pass
    return None


@pwndbg.lib.cache.cache_until("stop")
def is_readable_address(address: int) -> bool:
    """is_readable_address(address) -> bool

    Check if the address can be read by GDB.

    Arguments:
        address(int): Address to read

    Returns:
        :class:`bool`: Whether the address is readable.
    """
    # We use vmmap to check before `peek()` because accessing memory for embedded targets might be slow and expensive.
    return pwndbg.gdblib.vmmap.find(address) is not None and peek(address) is not None


def poke(address: int) -> bool:
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
        pwndbg.gdblib.events.pause(gdb.events.memory_changed)
        write(address, c)
    except gdb.MemoryError:
        return False
    finally:
        pwndbg.gdblib.events.unpause(gdb.events.memory_changed)

    return True


def string(addr: int, max: int = 4096) -> bytearray:
    """Reads a null-terminated string from memory.

    Arguments:
        addr(int): Address to read from
        max(int): Maximum string length (default 4096)

    Returns:
        An empty bytearray, or a NULL-terminated bytearray.
    """
    if peek(addr):
        data = read(addr, max, partial=True)

        try:
            return data[: data.index(b"\x00")]
        except ValueError:
            pass

    return bytearray()


def byte(addr: int) -> int:
    """byte(addr) -> int

    Read one byte at the specified address
    """
    return readtype(pwndbg.gdblib.typeinfo.uchar, addr)


def uchar(addr: int) -> int:
    """uchar(addr) -> int

    Read one ``unsigned char`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uchar, addr)


def ushort(addr: int) -> int:
    """ushort(addr) -> int

    Read one ``unisgned short`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.ushort, addr)


def uint(addr: int) -> int:
    """uint(addr) -> int

    Read one ``unsigned int`` at the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint, addr)


def pvoid(addr: int) -> int:
    """pvoid(addr) -> int

    Read one pointer from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.pvoid, addr)


def u8(addr: int) -> int:
    """u8(addr) -> int

    Read one ``uint8_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint8, addr)


def u16(addr: int) -> int:
    """u16(addr) -> int

    Read one ``uint16_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint16, addr)


def u32(addr: int) -> int:
    """u32(addr) -> int

    Read one ``uint32_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint32, addr)


def u64(addr: int) -> int:
    """u64(addr) -> int

    Read one ``uint64_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.uint64, addr)


def u(addr: int, size: int | None = None) -> int:
    """u(addr, size=None) -> int

    Read one ``unsigned`` integer from the specified address,
    with the bit-width specified by ``size``, which defaults
    to the pointer width.
    """
    if size is None:
        size = pwndbg.aglib.arch.ptrsize * 8
    return {8: u8, 16: u16, 32: u32, 64: u64}[size](addr)


def s8(addr: int) -> int:
    """s8(addr) -> int

    Read one ``int8_t`` from the specified address
    """
    return readtype(pwndbg.gdblib.typeinfo.int8, addr)


def s16(addr: int) -> int:
    """s16(addr) -> int

    Read one ``int16_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int16, addr)


def s32(addr: int) -> int:
    """s32(addr) -> int

    Read one ``int32_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int32, addr)


def s64(addr: int) -> int:
    """s64(addr) -> int

    Read one ``int64_t`` from the specified address.
    """
    return readtype(pwndbg.gdblib.typeinfo.int64, addr)


def cast_pointer(type: gdb.Type, addr: int | gdb.Value) -> gdb.Value:
    """Create a gdb.Value at given address and cast it to the pointer of specified type"""
    if isinstance(addr, int):
        addr = gdb.Value(addr)
    return addr.cast(type.pointer())


def get_typed_pointer(type: str | gdb.Type, addr: int | gdb.Value) -> gdb.Value:
    """Look up a type by name if necessary and return a gdb.Value of addr cast to that type"""
    if isinstance(type, str):
        gdb_type = pwndbg.gdblib.typeinfo.load(type)
        if gdb_type is None:
            raise ValueError(f"Type '{type}' not found")
    elif isinstance(type, gdb.Type):
        gdb_type = type
    else:
        raise ValueError(f"Invalid type: {type}")
    return cast_pointer(gdb_type, addr)


def get_typed_pointer_value(type_name: str | gdb.Type, addr: int | gdb.Value) -> gdb.Value:
    """Read the pointer value of addr cast to type specified by type_name"""
    return get_typed_pointer(type_name, addr).dereference()


@pwndbg.lib.cache.cache_until("stop")
def find_upper_boundary(addr: int, max_pages: int = 1024) -> int:
    """find_upper_boundary(addr, max_pages=1024) -> int

    Brute-force search the upper boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.lib.memory.page_align(int(addr))
    try:
        for _ in range(max_pages):
            read(addr, 1)
            # import sys
            # sys.stdout.write(hex(addr) + '\n')
            addr += PAGE_SIZE

            # Sanity check in case a custom GDB server/stub
            # incorrectly returns a result from read
            # (this is most likely redundant, but its ok to keep it?)
            if addr > pwndbg.aglib.arch.ptrmask:
                return pwndbg.aglib.arch.ptrmask
    except gdb.MemoryError:
        pass
    return addr


@pwndbg.lib.cache.cache_until("stop")
def find_lower_boundary(addr: int, max_pages: int = 1024) -> int:
    """find_lower_boundary(addr, max_pages=1024) -> int

    Brute-force search the lower boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.lib.memory.page_align(int(addr))
    try:
        for _ in range(max_pages):
            read(addr, 1)
            addr -= PAGE_SIZE

            # Sanity check (see comment in find_upper_boundary)
            if addr < 0:
                return 0

    except gdb.MemoryError:
        addr += PAGE_SIZE
    return addr


def update_min_addr() -> None:
    global MMAP_MIN_ADDR
    MMAP_MIN_ADDR = 0 if pwndbg.gdblib.qemu.is_qemu_kernel() else 0x8000


def fetch_struct_as_dictionary(
    struct_name: str,
    struct_address: int,
    include_only_fields: Set[str] | None = None,
    exclude_fields: Set[str] | None = None,
) -> GdbDict:
    struct_type = gdb.lookup_type("struct " + struct_name)
    fetched_struct = get_typed_pointer_value(struct_type, struct_address)

    return pack_struct_into_dictionary(fetched_struct, include_only_fields, exclude_fields)


def pack_struct_into_dictionary(
    fetched_struct: gdb.Value,
    include_only_fields: Set[str] | None = None,
    exclude_fields: Set[str] | None = None,
) -> GdbDict:
    struct_as_dictionary = {}

    if exclude_fields is None:
        exclude_fields = set()

    if include_only_fields is not None:
        for field_name in include_only_fields:
            key = field_name
            value = convert_gdb_value_to_python_value(fetched_struct[field_name])
            struct_as_dictionary[key] = value
    else:
        for field in fetched_struct.type.fields():
            if field.name is None:
                # Flatten anonymous structs/unions
                anon_type = convert_gdb_value_to_python_value(fetched_struct[field])
                assert isinstance(anon_type, dict)
                struct_as_dictionary.update(anon_type)
            elif field.name not in exclude_fields:
                key = field.name
                value = convert_gdb_value_to_python_value(fetched_struct[field])
                struct_as_dictionary[key] = value

    return struct_as_dictionary


def convert_gdb_value_to_python_value(gdb_value: gdb.Value) -> int | GdbDict:
    gdb_type = gdb_value.type.strip_typedefs()

    if gdb_type.code == gdb.TYPE_CODE_PTR or gdb_type.code == gdb.TYPE_CODE_INT:
        return int(gdb_value)
    elif gdb_type.code == gdb.TYPE_CODE_STRUCT:
        return pack_struct_into_dictionary(gdb_value)

    raise NotImplementedError


def resolve_renamed_struct_field(struct_name: str, possible_field_names: Set[str]) -> str:
    struct_type = gdb.lookup_type("struct " + struct_name)

    for field_name in possible_field_names:
        if gdb.types.has_field(struct_type, field_name):
            return field_name

    raise ValueError(f"Field name did not match any of {possible_field_names}.")
