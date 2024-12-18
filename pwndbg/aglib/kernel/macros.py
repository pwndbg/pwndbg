from __future__ import annotations

from typing import Iterator

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo


def container_of(ptr: int, typename: str, fieldname: str) -> pwndbg.dbg_mod.Value:
    obj_addr = int(ptr) - pwndbg.aglib.typeinfo.load(typename).offsetof(fieldname)
    return pwndbg.aglib.memory.get_typed_pointer(typename, obj_addr)


def for_each_entry(
    head: pwndbg.dbg_mod.Value, typename: str, field: str
) -> Iterator[pwndbg.dbg_mod.Value]:
    head_addr = int(head.address)
    addr = head["next"]
    addr_int = int(addr)
    while addr_int != head_addr:
        yield container_of(addr_int, typename, field)
        addr = addr.dereference()["next"]
        addr_int = int(addr)


def swab(x: int) -> int:
    return int(
        ((x & 0x00000000000000FF) << 56)
        | ((x & 0x000000000000FF00) << 40)
        | ((x & 0x0000000000FF0000) << 24)
        | ((x & 0x00000000FF000000) << 8)
        | ((x & 0x000000FF00000000) >> 8)
        | ((x & 0x0000FF0000000000) >> 24)
        | ((x & 0x00FF000000000000) >> 40)
        | ((x & 0xFF00000000000000) >> 56)
    )


def _arr(x: pwndbg.dbg_mod.Value, n: int) -> pwndbg.dbg_mod.Value:
    """returns the nth element of type x, starting at address of x"""
    ptr = x.address.cast(x.type.pointer())
    return (ptr + n).dereference()


def compound_head(page: pwndbg.dbg_mod.Value) -> pwndbg.dbg_mod.Value:
    """returns the head page of compound pages"""
    assert page.type.code == pwndbg.dbg_mod.TypeCode.STRUCT and page.type.name_identifier == "page"
    # https://elixir.bootlin.com/linux/v6.2/source/include/linux/page-flags.h#L249
    head = page["compound_head"]
    if int(head) & 1:
        return (head - 1).cast(page.type.pointer()).dereference()

    pg_headty = pwndbg.aglib.typeinfo.load("enum pageflags")
    assert pg_headty is not None, "Type 'enum pageflags' not found"
    pg_head = pg_headty.enum_member("PG_head")
    assert pg_head is not None, "Type 'enum pageflags' not found"

    # https://elixir.bootlin.com/linux/v6.2/source/include/linux/page-flags.h#L212
    if int(page["flags"]) & (1 << pg_head):
        next_page = _arr(page, 1)

        head = next_page["compound_head"]
        if int(head) & 1:
            return (head - 1).cast(page.type.pointer()).dereference()

    return page
