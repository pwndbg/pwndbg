from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pwndbg.aglib.qemu
import pwndbg.aglib.stack
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.dbg_mod
import pwndbg.lib.memory
import pwndbg.lib.pretty_print
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


def get_address_and_symbol(
    address: int, decompiler_stack_variables: dict[int, str], respect_ptrwidth: bool = False
) -> str:
    """
    Convert and colorize address 0x7ffff7fcecd0 to string `0x7ffff7fcecd0 (_dl_fini)`
    If no symbol exists for the address, return colorized address.

    Args:
        respect_ptrwidth: Align value to pointer width, i.e. would output
            `0x00007ffff7fcecd0 (_dl_fini)`.
    """
    symbol = pwndbg.aglib.symbol.resolve_addr(address)
    ptralignment: int = pwndbg.aglib.arch.ptrbits if respect_ptrwidth else -1
    if symbol:
        symbol = pwndbg.lib.pretty_print.int_to_string(address, ptralignment) + f" ({symbol})"
    else:
        var: str | None = pwndbg.aglib.stack.get_stack_var_name(address)
        if var is None:
            var = decompiler_stack_variables.get(address)
        if var is not None:
            symbol = pwndbg.lib.pretty_print.int_to_string(address, ptralignment) + f" {{{var}}}"
    return get(address, symbol, respect_ptrwidth=respect_ptrwidth)


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
    address: int | pwndbg.dbg_mod.Value | Any,
    text: str | None = None,
    prefix: str | None = None,
    page: pwndbg.lib.memory.Page | None = None,
    respect_ptrwidth: bool = False,
) -> str:
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address: Address to look up
        text: Optional text to use in place of the address in the return value string.
        prefix: Optional text to set at beginning in the return value string, followed by a space, without modifiying the original text.
        respect_ptrwidth: Pad value with leading zeroes so that it is pointer-sized.
    """
    address = int(address)
    if page is None:  # if we know the containing page, don't bother to find it as an optimization
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
    elif "[heap" in page.objfile or (
        pwndbg.aglib.qemu.is_qemu_kernel()
        and any(keyword in page.objfile for keyword in ("physmap", "vmalloc", "slab virtual"))
    ):
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
        ptralignment: int = pwndbg.aglib.arch.ptrbits if respect_ptrwidth else -1
        text = pwndbg.lib.pretty_print.int_to_string(address, adhere_to_ptrwidth=ptralignment)

    if prefix is not None:
        # Prepend the prefix and a space before the existing text
        text = f"{prefix} {text}"

    return color(text)


def legend() -> str:
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
