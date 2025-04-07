from __future__ import annotations

from typing import Dict
from typing import Set
from typing import Union

import pwndbg.aglib.arch
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg import EventType
from pwndbg.dbg import TypeCode
from pwndbg.lib.memory import PAGE_SIZE

GdbDict = Dict[str, Union["GdbDict", int]]


MMAP_MIN_ADDR = 0x8000


def read(addr: int, count: int, partial: bool = False) -> bytearray:
    """read(addr, count, partial=False) -> bytearray

    Read memory from the program being debugged.

    Arguments:
        addr: Address to read
        count: Number of bytes to read
        partial: Whether less than ``count`` bytes can be returned

    Returns:
        `bytearray` The memory at the specified address,
        or ``None``.
    """
    return pwndbg.dbg.selected_inferior().read_memory(address=addr, size=count, partial=partial)


def readtype(type: pwndbg.dbg_mod.Type, addr: int) -> int:
    """readtype(type, addr) -> int

    Reads an integer-type (e.g. ``uint64``) and returns a Python
    native integer representation of the same.

    Arguments:
        type: GDB type to read
        addr: Address at which the value to be read resides

    Returns:
        `int`
    """
    return int(get_typed_pointer_value(type, addr))


def write(addr: int, data: str | bytes | bytearray) -> None:
    """write(addr, data)

    Writes data into the memory of the process being debugged.

    Arguments:
        addr: Address to write
        data: Data to write
    """
    if isinstance(data, str):
        data = bytes(data, "utf8")

    pwndbg.dbg.selected_inferior().write_memory(address=addr, data=bytearray(data), partial=False)


def peek(address: int) -> bytearray | None:
    """peek(address) -> bytearray

    Read one byte from the specified address.

    Arguments:
        address: Address to read

    Returns:
        `bytearray` A single byte of data, or ``None`` if the
        address cannot be read.
    """
    try:
        return read(address, 1)
    except Exception:
        pass
    return None


@pwndbg.lib.cache.cache_until("stop")
def is_readable_address(address: int) -> bool:
    """is_readable_address(address) -> bool

    Check if the address can be read by GDB.

    Arguments:
        address: Address to read

    Returns:
        `bool`: Whether the address is readable.
    """
    # We use vmmap to check before `peek()` because accessing memory for embedded targets might be slow and expensive.
    return pwndbg.aglib.vmmap.find(address) is not None and peek(address) is not None


def poke(address: int) -> bool:
    """poke(address)

    Checks whether an address is writable.

    Arguments:
        address: Address to check

    Returns:
        `bool`: Whether the address is writable.
    """
    c = peek(address)
    if c is None:
        return False
    try:
        # Suspending mem_changed event during poke speeds up things when vmmaps are explored
        # (e.g. when stepping through remote processes run with QEMU)
        # The suspension prevents the clearing of the disasm instruction cache
        # by `aglib.disasm.clear_on_reg_mem_change`
        pwndbg.dbg.suspend_events(EventType.MEMORY_CHANGED)
        write(address, c)
    except Exception:
        return False
    finally:
        pwndbg.dbg.resume_events(EventType.MEMORY_CHANGED)

    return True


def string(addr: int, max: int = 4096) -> bytearray:
    """Reads a null-terminated string from memory.

    Arguments:
        addr: Address to read from
        max: Maximum string length (default 4096)

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
    return readtype(pwndbg.aglib.typeinfo.uchar, addr)


def uchar(addr: int) -> int:
    """uchar(addr) -> int

    Read one ``unsigned char`` at the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uchar, addr)


def ushort(addr: int) -> int:
    """ushort(addr) -> int

    Read one ``unisgned short`` at the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.ushort, addr)


def uint(addr: int) -> int:
    """uint(addr) -> int

    Read one ``unsigned int`` at the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uint, addr)


def pvoid(addr: int) -> int:
    """pvoid(addr) -> int

    Read one pointer from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.pvoid, addr)


def u8(addr: int) -> int:
    """u8(addr) -> int

    Read one ``uint8_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uint8, addr)


def u16(addr: int) -> int:
    """u16(addr) -> int

    Read one ``uint16_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uint16, addr)


def u32(addr: int) -> int:
    """u32(addr) -> int

    Read one ``uint32_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uint32, addr)


def u64(addr: int) -> int:
    """u64(addr) -> int

    Read one ``uint64_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.uint64, addr)


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
    return readtype(pwndbg.aglib.typeinfo.int8, addr)


def s16(addr: int) -> int:
    """s16(addr) -> int

    Read one ``int16_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.int16, addr)


def s32(addr: int) -> int:
    """s32(addr) -> int

    Read one ``int32_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.int32, addr)


def s64(addr: int) -> int:
    """s64(addr) -> int

    Read one ``int64_t`` from the specified address.
    """
    return readtype(pwndbg.aglib.typeinfo.int64, addr)


def cast_pointer(
    type: pwndbg.dbg_mod.Type, addr: int | pwndbg.dbg_mod.Value
) -> pwndbg.dbg_mod.Value:
    """Create a Value containing given address and cast it to the pointer of specified type"""
    if isinstance(addr, int):
        addr = pwndbg.dbg.selected_inferior().create_value(addr)
    return addr.cast(type.pointer())


def get_typed_pointer(
    type: str | pwndbg.dbg_mod.Type, addr: int | pwndbg.dbg_mod.Value
) -> pwndbg.dbg_mod.Value:
    """Look up a type by name if necessary and return a Value of addr cast to that type"""
    if isinstance(type, str):
        real_type = pwndbg.aglib.typeinfo.load(type)
        if real_type is None:
            raise ValueError(f"Type '{type}' not found")
    elif isinstance(type, pwndbg.dbg_mod.Type):
        real_type = type
    else:
        raise ValueError(f"Invalid type: {type}")
    return cast_pointer(real_type, addr)


def get_typed_pointer_value(
    type_name: str | pwndbg.dbg_mod.Type, addr: int | pwndbg.dbg_mod.Value
) -> pwndbg.dbg_mod.Value:
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
    except pwndbg.dbg_mod.Error:
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

    except pwndbg.dbg_mod.Error:
        addr += PAGE_SIZE
    return addr


def update_min_addr() -> None:
    global MMAP_MIN_ADDR
    MMAP_MIN_ADDR = 0 if pwndbg.aglib.qemu.is_qemu_kernel() else 0x8000


def fetch_struct_as_dictionary(
    struct_name: str,
    struct_address: int | pwndbg.dbg_mod.Value,
    include_only_fields: Set[str] | None = None,
    exclude_fields: Set[str] | None = None,
) -> GdbDict:
    fetched_struct = get_typed_pointer_value("struct " + struct_name, struct_address)
    return pack_struct_into_dictionary(fetched_struct, include_only_fields, exclude_fields)


def pack_struct_into_dictionary(
    fetched_struct: pwndbg.dbg_mod.Value,
    include_only_fields: Set[str] | None = None,
    exclude_fields: Set[str] | None = None,
) -> GdbDict:
    struct_as_dictionary = {}

    if exclude_fields is None:
        exclude_fields = set()

    if include_only_fields is not None:
        for field_name in include_only_fields:
            key = field_name
            value = convert_pwndbg_value_to_python_value(fetched_struct[field_name])
            struct_as_dictionary[key] = value
    else:
        for index, field in enumerate(fetched_struct.type.fields()):
            if field.name is None:
                # Flatten anonymous structs/unions
                anon_type = convert_pwndbg_value_to_python_value(fetched_struct[index])
                assert isinstance(anon_type, dict)
                struct_as_dictionary.update(anon_type)
            elif field.name not in exclude_fields:
                key = field.name
                value = convert_pwndbg_value_to_python_value(fetched_struct[index])
                struct_as_dictionary[key] = value

    return struct_as_dictionary


def convert_pwndbg_value_to_python_value(dbg_value: pwndbg.dbg_mod.Value) -> int | GdbDict:
    ty = dbg_value.type.strip_typedefs()

    if ty.code == TypeCode.POINTER or ty.code == TypeCode.INT:
        return int(dbg_value)
    elif ty.code == TypeCode.STRUCT:
        return pack_struct_into_dictionary(dbg_value)

    raise NotImplementedError


def resolve_renamed_struct_field(struct_name: str, possible_field_names: Set[str]) -> str:
    struct_types = pwndbg.dbg.selected_inferior().types_with_name(f"struct {struct_name}")
    if len(struct_types) == 0:
        raise pwndbg.dbg_mod.Error(f"could not find type 'struct {struct_name}'")
    struct_type = struct_types[0]

    for field_name in possible_field_names:
        if struct_type.has_field(field_name):
            return field_name

    raise ValueError(f"Field name did not match any of {possible_field_names}.")
