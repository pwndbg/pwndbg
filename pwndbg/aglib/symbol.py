"""
Looking up addresses for function names / symbols, and
vice-versa.
"""

from __future__ import annotations

import pwndbg.lib.cache


def lookup_global_symbol_addr(
    name: str, *, symbol_type=None, prefer_static: bool = False
) -> int | None:
    s = lookup_global_symbol(name, symbol_type=symbol_type)
    if not s:
        return None
    addr = s.address
    if not addr:
        return None
    return int(addr)


def lookup_global_symbol_value(
    name: str, *, symbol_type=None, prefer_static: bool = False
) -> int | None:
    s = lookup_global_symbol(name, symbol_type=symbol_type)
    if not s:
        return None
    return int(s)


# TODO: cache here?
def lookup_global_symbol(
    name: str, *, symbol_type=None, prefer_static: bool = False
) -> pwndbg.dbg_mod.Value | None:
    """
    - function
    - variable
    - any

    Lookup in order:
    - global scope

    Variable types order when prefer_static=True:
    - static
    - normal

    Variable types order when prefer_static=False:
    - normal
    """
    # function / variables
    pass


def lookup_symbol_addr(name: str, *, symbol_type=None) -> int | None:
    s = lookup_symbol(name, symbol_type=symbol_type)
    if not s:
        return None
    addr = s.address
    if not addr:
        return None
    return int(addr)


def lookup_symbol_value(name: str, *, symbol_type=None) -> int | None:
    s = lookup_symbol(name, symbol_type=symbol_type)
    if not s:
        return None
    # TODO: co jak value, nie jest intem?
    return int(s)


# TODO: cache here?
def lookup_symbol(name: str, *, symbol_type=None) -> pwndbg.dbg_mod.Value | None:
    """
    It will search:
    - functions names
    - variables names
    - typedef names
    - enum names

    Lookup in order:
    - local scope
    - global your module scope
    - global other module scope
    """
    pass


@pwndbg.lib.cache.cache_until("objfile")
def resolve_addr(addr: int) -> str | None:
    """
    Lookup in order:
    - local scope
    - global scope
    """
    return pwndbg.dbg.selected_inferior().symbol_name_at_address(addr)
