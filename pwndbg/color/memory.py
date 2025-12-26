from __future__ import annotations

from typing import Any
from typing import Callable

import pwndbg.aglib.stack
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
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


def get_address_and_symbol(address: int, decompiler_stack_variables: dict[int, str]) -> str:
    """
    Convert and colorize address 0x7ffff7fcecd0 to string `0x7ffff7fcecd0 (_dl_fini)`
    If no symbol exists for the address, return colorized address
    """
    symbol = pwndbg.aglib.symbol.resolve_addr(address)
    if symbol:
        symbol = f"{address:#x} ({symbol})"
    else:
        var: str | None = pwndbg.aglib.stack.get_stack_var_name(address)
        if var is None:
            var = decompiler_stack_variables.get(address)
        if var is not None:
            symbol = f"{address:#x} {{{var}}}"
    return get(address, symbol)


def get_address_or_symbol(address: int, decompiler_stack_variables: dict[int, str]) -> str:
    """
    Convert and colorize address to symbol if it can be resolved, else return colorized address
    """
    return attempt_colorized_symbol(address, decompiler_stack_variables) or get(address)


def attempt_colorized_symbol(
    address: int, decompiler_stack_variables: dict[int, str]
) -> str | None:
    """
    Convert address to colorized symbol (if symbol is there), else None
    """
    symbol = pwndbg.aglib.symbol.resolve_addr(address)
    if symbol:
        return get(address, symbol)
    else:
        var: str | None = pwndbg.aglib.stack.get_stack_var_name(address)
        if var is None:
            var = decompiler_stack_variables.get(address)
        if var is not None:
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
        prefix: Optional text to set at beginning in the return value string, followed by a space, without modifiying the original text.
    """
    address = int(address)
    page = pwndbg.aglib.vmmap.find(address)

    color: Callable[[str], str]

    if page is None:
        color = normal
    elif "[stack" in page.objfile:
        color = c.stack
    elif page.execute:
        color = c.code
    elif not page.write:
        color = c.rodata
    elif any(keyword in page.objfile for keyword in ("[heap", "physmap", "vmalloc")):
        color = c.heap
    elif page.rw:
        color = c.data
    elif page.is_guard:
        color = c.guard
    else:
        color = c.rodata

    if page and page.wx:
        old_color = color
        color = lambda x: c.wx(old_color(x))

    if text is None:
        text = pwndbg.lib.pretty_print.int_to_string(address)

    if prefix is not None:
        # Prepend the prefix and a space before the existing text
        text = f"{prefix} {text}"

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
