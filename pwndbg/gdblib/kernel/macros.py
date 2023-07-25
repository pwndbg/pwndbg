from __future__ import annotations

import gdb


def offset_of(typename: str, fieldname: str):
    ptr_type = gdb.lookup_type(typename).pointer()
    dummy = gdb.Value(0).cast(ptr_type)
    return int(dummy[fieldname].address)


def container_of(ptr, typename: str, fieldname: str):
    ptr_type = gdb.lookup_type(typename).pointer()
    obj_addr = int(ptr) - offset_of(typename, fieldname)
    return gdb.Value(obj_addr).cast(ptr_type)


def for_each_entry(head, typename: str, field):
    addr = head["next"]
    while addr != head.address:
        yield container_of(addr, typename, field)
        addr = addr.dereference()["next"]


def swab(x):
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


def _arr(x: gdb.Value, n: int) -> gdb.Value:
    """returns the nth element of type x, starting at address of x"""
    ptr = x.address.cast(x.type.pointer())
    return (ptr + n).dereference()


def compound_head(page: gdb.Value) -> gdb.Value:
    """returns the head page of compound pages"""
    assert page.type.name == "page"
    # https://elixir.bootlin.com/linux/v6.2/source/include/linux/page-flags.h#L249
    head = page["compound_head"]
    if int(head) & 1:
        return (head - 1).cast(page.type.pointer()).dereference()

    pg_head = int(gdb.lookup_static_symbol("PG_head").value())
    # https://elixir.bootlin.com/linux/v6.2/source/include/linux/page-flags.h#L212
    if int(page["flags"]) & (1 << pg_head):
        next_page = _arr(page, 1)

        head = next_page["compound_head"]
        if int(head) & 1:
            return (head - 1).cast(page.type.pointer()).dereference()

    return page
