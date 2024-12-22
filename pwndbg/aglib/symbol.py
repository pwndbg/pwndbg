"""
Looking up addresses for function names / symbols, and
vice-versa.
"""

from __future__ import annotations

import pwndbg.integration
import pwndbg.lib.cache
from pwndbg.dbg import SymbolLookupType


def lookup_symbol_addr(
    name: str,
    *,
    prefer_static: bool = False,
    type: SymbolLookupType = SymbolLookupType.ANY,
    objfile_endswith: str | None = None,
) -> int | None:
    addr = lookup_symbol(
        name, type=type, prefer_static=prefer_static, objfile_endswith=objfile_endswith
    )
    if not addr:
        return None
    return int(addr)


def lookup_symbol_value(
    name: str,
    *,
    prefer_static: bool = False,
    type: SymbolLookupType = SymbolLookupType.ANY,
    objfile_endswith: str | None = None,
) -> int | None:
    addr = lookup_symbol(
        name, type=type, prefer_static=prefer_static, objfile_endswith=objfile_endswith
    )
    if not addr:
        return None

    value = addr.dereference()
    if not value:
        return None
    return int(value)


# TODO: cache here? can we cache obj 'Value'?
def lookup_symbol(
    name: str,
    *,
    prefer_static: bool = False,
    type: SymbolLookupType = SymbolLookupType.ANY,
    objfile_endswith: str | None = None,
) -> pwndbg.dbg_mod.Value | None:
    """
    Returns the address of the given `symbol`, cast-ed to the appropriate symbol type.

    This function searches for (SymbolLookupType.ANY):
    - Function names
    - Variable names
    - (gdb only) Typedef names (if you need please use aglib.typeinfo.load)
    - (gdb only) Enum values (if you need please use aglib.typeinfo.enum_member)

    The lookup order is as follows (default):
    1. Global scope within the current module
    2. Global static scope within the current module
    3. Global scope in other modules
    4. Global static scope in other modules
    """
    return pwndbg.dbg.selected_inferior().lookup_symbol(
        name, type=type, prefer_static=prefer_static, objfile_endswith=objfile_endswith
    )


# TODO: cache here? can we cache obj 'Value'?
def lookup_frame_symbol(
    name: str, *, type: SymbolLookupType = SymbolLookupType.ANY
) -> pwndbg.dbg_mod.Value | None:
    """
    Returns the address of the given `symbol`, cast-ed to the appropriate symbol type.

    This function searches for (SymbolLookupType.ANY):
    - Function names
    - Variable names
    - (gdb only, please don't use) Typedef names
    - (gdb only, please don't use) Enum values

    The lookup order is as follows:
    1. Local scope
    2. Global scope within the current module
    3. Global static scope within the current module
    4. Global scope in other modules
    5. Global static scope in other modules
    """
    return pwndbg.dbg.selected_frame().lookup_symbol(name, type=type)


@pwndbg.lib.cache.cache_until("objfile")
def resolve_addr(addr: int) -> str | None:
    """
    Resolves an address to its corresponding symbol name, if available.

    Note:
    - This function does not resolve TLS (Thread-Local Storage) addresses or addresses with local scope.

    Resolution is performed in the following order:
    - Global scope symbols.
    """
    assert addr >= 0, "address must be positive"

    symbol_name = pwndbg.dbg.selected_inferior().symbol_name_at_address(addr)
    if symbol_name:
        return symbol_name

    return pwndbg.integration.provider.get_symbol(addr)
