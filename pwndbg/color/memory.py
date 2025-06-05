from __future__ import annotations

from typing import Any
from typing import Callable

import pwndbg.integration
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import normal

ColorFunction = Callable[[str], str]

c = ColorConfig(
    "memory",
    [
        ColorParamSpec("stack", "yellow", "color for stack memory"),
        ColorParamSpec("heap", "blue", "color for heap memory"),
        ColorParamSpec("code", "red", "color for executable memory"),
        ColorParamSpec("data", "purple", "color for all other writable memory"),
        ColorParamSpec("rodata", "normal", "color for all read only memory"),
        ColorParamSpec("wx", "underline", "color added to all WX memory"),
        ColorParamSpec("guard", "cyan", "color added to all guard pages (no perms)"),
    ],
)


def get_address_and_symbol(address: int) -> str:
    """
    Convert and colorize address 0x7ffff7fcecd0 to string `0x7ffff7fcecd0 (_dl_fini)`
    If no symbol exists for the address, return colorized address
    """
    symbol = pwndbg.aglib.symbol.resolve_addr(address)
    if symbol:
        symbol = f"{address:#x} ({symbol})"
    else:
        page = pwndbg.aglib.vmmap.find(address)
        if page and "[stack" in page.objfile:
            var = pwndbg.integration.provider.get_stack_var_name(address)
            if var:
                symbol = f"{address:#x} {{{var}}}"
    return get(address, symbol)


def get_address_or_symbol(address: int) -> str:
    """
    Convert and colorize address to symbol if it can be resolved, else return colorized address
    """
    return attempt_colorized_symbol(address) or get(address)


def attempt_colorized_symbol(address: int) -> str | None:
    """
    Convert address to colorized symbol (if symbol is there), else None
    """
    symbol = pwndbg.aglib.symbol.resolve_addr(address)
    if symbol:
        return get(address, symbol)
    else:
        page = pwndbg.aglib.vmmap.find(address)
        if page and "[stack" in page.objfile:
            var = pwndbg.integration.provider.get_stack_var_name(address)
            if var:
                return get(address, f"{{{var}}}")
    return None


# We have to accept `Any` here, as users may pass gdb.Value objects to this
# function. This is probably more lenient than we'd really like.
#
# TODO: Remove the exception for gdb.Value case from `pwndbg.color.memory.get`.
def get(
    address: int | pwndbg.dbg_mod.Value | Any, text: str | None = None, prefix: str | None = None
) -> str:
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address: Address to look up
        text: Optional text to use in place of the address in the return value string.
        prefix: Optional text to set at beginning in the return value string.
    """
    address = int(address)
    page = pwndbg.aglib.vmmap.find(address)

    color: Callable[[str], str]

    if page is None:
        color = normal
    elif "[stack" in page.objfile:
        color = c.stack
    elif "[heap" in page.objfile:
        color = c.heap
    elif page.execute:
        color = c.code
    elif page.rw:
        color = c.data
    elif page.is_guard:
        color = c.guard
    else:
        color = c.rodata

    if page and page.wx:
        old_color = color
        color = lambda x: c.wx(old_color(x))

    if text is None and isinstance(address, int) and address > 255:
        text = hex(int(address))
    if text is None:
        text = str(int(address))

    if prefix:
        # Replace first N characters with the provided prefix
        text = prefix + text[len(prefix) :]

    return color(text)


def legend():
    return "LEGEND: " + " | ".join(
        (
            c.stack("STACK"),
            c.heap("HEAP"),
            c.code("CODE"),
            c.data("DATA"),
            # WX segments will also be marked as code, so do 2 formatters here
            c.wx(c.code("WX")),
            c.rodata("RODATA"),
        )
    )
