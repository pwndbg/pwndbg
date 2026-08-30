from __future__ import annotations

from collections.abc import Callable
from string import printable
from typing import TypeGuard
from typing import Union

import pwndbg.aglib
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg_mod import EventType
from pwndbg.dbg_mod import TypeCode
from pwndbg.lib import TypeNotFoundError
from pwndbg.lib.memory import PAGE_SIZE

GdbDict = dict[str, Union["GdbDict", int]]


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

    Raises:
        TypeNotFoundError: If the type does not exist in the debugger.

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


def is_readable_or_nil_ptr(address: int) -> bool:
    return True if address == 0 else is_readable_address(address)


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


def read_pointer_width(addr: int) -> int:
    """
    Read one pointer-width integer at the specified address.

    Raises:
        pwndbg.dbg_mod.Error: if memory read fails.
    """
    return pwndbg.aglib.arch.unpack(read(addr, pwndbg.aglib.arch.ptrsize))


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
        size = pwndbg.aglib.arch.ptrbits
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


def sint(addr: int) -> int:
    """
    Read one `signed int` from the specified
    address.
    """
    return readtype(pwndbg.aglib.typeinfo.sint, addr)


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
    """
    Look up a type by name if necessary and return a Value of addr cast to that type.

    Raises:
        TypeNotFoundError: If the type does not exist in the debugger.
    """
    if addr is None:
        return None
    if isinstance(type, str):
        real_type = pwndbg.aglib.typeinfo.load(type)
        if real_type is None:
            raise TypeNotFoundError(f"Type '{type}' not found")
    elif isinstance(type, pwndbg.dbg_mod.Type):
        real_type = type
    else:
        raise ValueError(f"Invalid type: {type}")
    return cast_pointer(real_type, addr)


def get_typed_pointer_value(
    type_name: str | pwndbg.dbg_mod.Type, addr: int | pwndbg.dbg_mod.Value
) -> pwndbg.dbg_mod.Value:
    """
    Read the pointer value of addr cast to type specified by type_name.

    Raises:
        TypeNotFoundError: If the type does not exist in the debugger.
    """
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
    include_only_fields: set[str] | None = None,
    exclude_fields: set[str] | None = None,
) -> GdbDict:
    """
    Raises:
        TypeNotFoundError: If the type does not exist in the debugger.
    """
    fetched_struct = get_typed_pointer_value("struct " + struct_name, struct_address)
    return pack_struct_into_dictionary(fetched_struct, include_only_fields, exclude_fields)


def pack_struct_into_dictionary(
    fetched_struct: pwndbg.dbg_mod.Value,
    include_only_fields: set[str] | None = None,
    exclude_fields: set[str] | None = None,
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

    if ty.code in (TypeCode.POINTER, TypeCode.INT):
        return int(dbg_value)
    if ty.code == TypeCode.STRUCT:
        return pack_struct_into_dictionary(dbg_value)

    raise NotImplementedError


def resolve_renamed_struct_field(struct_name: str, possible_field_names: set[str]) -> str:
    struct_types = pwndbg.dbg.selected_inferior().types_with_name(f"struct {struct_name}")
    if len(struct_types) == 0:
        raise pwndbg.dbg_mod.Error(f"could not find type 'struct {struct_name}'")
    struct_type = struct_types[0]

    for field_name in possible_field_names:
        if struct_type.has_field(field_name):
            return field_name

    raise ValueError(f"Field name did not match any of {possible_field_names}.")


@pwndbg.lib.cache.cache_until("start", "objfile")
def is_pagefault_supported() -> bool:
    """
    This function should be called before stray memory dereferences to protect against the following situations:

    1. On embedded systems, it's not uncommon for MMIO regions to exist where memory reads might mutate the hardware/process state.
    2. On baremetal/embedded, paging doesn't always exist, so all memory is "valid" (and often initialized to zero) - this makes every value appear to be a pointer.

    As such, we disable dereferencing by default for bare metal targets.

    See more discussion here: https://github.com/pwndbg/pwndbg/pull/385
    """

    # TODO: use a better detection method
    return pwndbg.dbg.selected_inferior().is_linux()


def is_kernel(addr: int | None) -> TypeGuard[int]:
    return addr is not None and (addr >> 63 == 1) and peek(addr) is not None


VALID_CHARS = list(map(ord, set(printable) - set("\t\r\n\x0c\x0b")))


def bin_ascii(bs: bytes | bytearray | list[int]) -> str:
    return "".join(chr(c) if c in VALID_CHARS else "." for c in bs)


def pprint_blocks(
    start: int,
    block_delims: list[int],
    color_funcs: list[Callable[[object], str]],
    labels_map: dict[int, list[str]],
    cell_size: int,
    no_truncate: bool,
    no_skip: bool,
) -> None:
    """
    Pretty-prints specified memory range, changing colors at provided boundaries.
    """

    # round up to align with 4*cell_size and get half
    half_max_size = (
        pwndbg.lib.memory.round_up(int(pwndbg.config.max_visualize_chunk_size), cell_size << 2) >> 1
    )

    printed = 0
    out = ""
    asc = ""

    # For collapsing repeated lines
    skip_repeating: bool = False if no_skip else bool(pwndbg.config.vis_skip_repeating_val)
    prev_line_content: str | None = None
    repeat_count: int = 0
    line_buffer: str = ""  # Temporary buffer for building current line (holds first cell)
    saved_line_addr: str = ""  # Saved address for the current line

    def flush_repeats() -> None:
        """Add collapse message for accumulated repeated lines."""
        nonlocal out, repeat_count, prev_line_content
        if repeat_count > 0:
            out += f"\n\t... ↓     {repeat_count:>3} repeated lines skipped"
            repeat_count = 0
        prev_line_content = None

    labels = []
    cursor = start

    for c, stop in enumerate(block_delims):
        color_func = color_funcs[c % len(color_funcs)]

        first_cut = True
        # round down to align with 2*cell_size
        begin_addr = pwndbg.lib.memory.round_down(cursor, cell_size << 1)
        end_addr = pwndbg.lib.memory.round_down(stop, cell_size << 1)

        # Reset repeat tracking at block boundaries (only if skip_repeating is enabled)
        if skip_repeating:
            flush_repeats()

        while cursor != stop:
            # skip the middle part of a huge block
            if (
                not no_truncate
                and half_max_size > 0
                and begin_addr + half_max_size <= cursor < end_addr - half_max_size
            ):
                if first_cut:
                    out += "\n" + "." * len(hex(cursor))
                    first_cut = False
                cursor += cell_size
                continue

            if printed % 2 == 0:
                saved_line_addr = f"0x{cursor:x}"

            data = pwndbg.aglib.memory.read(cursor, cell_size)
            cell = pwndbg.aglib.arch.unpack(data)
            cell_hex = f"\t0x{cell:0{cell_size * 2}x}"

            # Temporarily store colored cell_hex
            colored_cell_hex = color_func(cell_hex)

            printed += 1

            labels.extend(labels_map.get(cursor, []))

            # Build up the cell part (2 cells per line)
            asc += bin_ascii(data)

            if printed % 2 == 1:
                # First cell of the line, just accumulate
                line_buffer += colored_cell_hex
            else:
                # Second cell - complete the line
                line_label_part = "\t <-- " + ", ".join(labels) if labels else ""
                colored_asc = color_func(asc)

                # Build complete line content (address + cells + ascii + labels)
                complete_line = (
                    ("\n" if out else "")
                    + saved_line_addr
                    + line_buffer
                    + colored_cell_hex
                    + "\t"
                    + colored_asc
                    + line_label_part
                )

                if skip_repeating:
                    # When skip_repeating is enabled, check for and collapse repeated lines
                    # Don't collapse lines with labels (they're important markers)
                    if not labels:
                        # Compare just the hex values and ASCII part (exclude address and labels)
                        current_hex_and_ascii = line_buffer + colored_cell_hex + "\t" + asc
                        if prev_line_content == current_hex_and_ascii:
                            # This line repeats the previous one, increment counter
                            repeat_count += 1
                        else:
                            # Different line, flush any accumulated repeats and output this line
                            flush_repeats()
                            out += complete_line
                            prev_line_content = current_hex_and_ascii
                    else:
                        # Line has labels, always output it
                        flush_repeats()
                        out += complete_line
                        prev_line_content = None
                else:
                    # When skip_repeating is disabled, output every line directly
                    out += complete_line

                # Reset line building vars
                line_buffer = ""
                asc = ""
                labels = []

            cursor += cell_size

    # Flush any remaining repeats (only matters if skip_repeating is enabled)
    if skip_repeating:
        flush_repeats()

    if printed % 2 != 0:
        # We have an incomplete line with only one cell
        # Need to add the address, first cell, and padding
        machine_word_string_length = 2 + (2 * cell_size)
        out += (
            ("\n" if out else "")
            + saved_line_addr
            + line_buffer
            + "\t"
            + " " * machine_word_string_length
            + "\t"
            + color_func(asc)
        )

    print(out)
