from __future__ import annotations

from typing import List

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.color.memory as M
import pwndbg.enhance
import pwndbg.integration
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import theme

LIMIT = pwndbg.config.add_param(
    "dereference-limit", 5, "max number of pointers to dereference in a chain"
)

c = ColorConfig(
    "chain",
    [
        ColorParamSpec("arrow", "normal", "color of chain formatting (arrow)"),
        ColorParamSpec(
            "contiguous-marker", "normal", "color of chain formatting (contiguous marker)"
        ),
    ],
)


def get(
    address: int | None,
    limit: int = LIMIT,
    offset: int = 0,
    hard_stop: int | None = None,
    hard_end: int = 0,
    include_start: bool = True,
    safe_linking: bool = False,
) -> List[int] | None:
    """
    Recursively dereferences an address. For bare metal, it will stop when the address is not in any of vmmap pages to avoid redundant dereference.

    Arguments:
        address: the first address to begin dereferencing
        limit: number of valid pointers
        offset: offset into the address to get the next pointer
        hard_stop: address to stop at
        hard_end: value to append when hard_stop is reached
        include_start: whether to include starting address or not
        safe_linking: whether this chain use safe-linking

    Returns:
        A list representing pointers of each ```address``` and reference
    """
    if address is None:
        return None
    assert address >= 0, "address must be positive"

    limit = int(limit)

    result = [address] if include_start else []
    for _ in range(limit):
        # Don't follow cycles, except to stop at the second occurrence.
        if result.count(address) >= 2:
            break

        if hard_stop is not None and address == hard_stop:
            result.append(hard_end)
            break

        try:
            address = address + offset

            # Avoid redundant dereferences in bare metal mode by checking
            # if address is in any of vmmap pages
            if not pwndbg.dbg.selected_inferior().is_linux() and not pwndbg.aglib.vmmap.find(
                address
            ):
                break

            next_address = int(
                pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.ppvoid, address)
            )
            address = next_address ^ ((address >> 12) if safe_linking else 0)
            address &= pwndbg.aglib.arch.ptrmask
            result.append(address)
        except pwndbg.dbg_mod.Error:
            break

    return result


config_arrow_left = theme.add_param("chain-arrow-left", "◂—", "left arrow of chain formatting")
config_arrow_right = theme.add_param("chain-arrow-right", "—▸", "right arrow of chain formatting")
config_contiguous = theme.add_param(
    "chain-contiguous-marker", "...", "contiguous marker of chain formatting"
)


def format(
    value: int | List[int] | None,
    limit: int = LIMIT,
    code: bool = True,
    offset: int = 0,
    hard_stop: int | None = None,
    hard_end: int = 0,
    safe_linking: bool = False,
    enhance_string_len: int | None = None,
) -> str:
    """
    Recursively dereferences an address into string representation, or convert the list representation
    of address dereferences into string representation.

    Arguments:
        value: Either the starting address to be sent to get, or the result of get (a list)
        limit: Number of valid pointers
        code: Hint that indicates the value may be an instruction
        offset: Offset into the address to get the next pointer
        hard_stop: Value to stop on
        hard_end: Value to append when hard_stop is reached: null, value of hard stop, a string.
        safe_linking: whether this chain use safe-linking
        enhance_string_len: The length of string to display for enhancement of the last pointer
    Returns:
        A string representing pointers of each address and reference
        Strings format: 0x0804a10 —▸ 0x08061000 ◂— 0x41414141
    """
    if value is None:
        return "<unavailable>"

    limit = int(limit)

    # Allow results from get function to be passed to format
    if isinstance(value, list):
        chain = value
    else:
        chain = get(value, limit, offset, hard_stop, hard_end, safe_linking=safe_linking) or []

    arrow_left = c.arrow(f" {config_arrow_left} ")
    arrow_right = c.arrow(f" {config_arrow_right} ")

    # Colorize the chain
    rest = [M.get_address_and_symbol(addr) if addr >= 0 else "" for addr in chain]

    # If the dereference limit is zero, skip any enhancements.
    if limit == 0:
        return rest[0]
    # Otherwise replace last element with the enhanced information.
    rest = rest[:-1]

    # Enhance the last entry
    # If there are no pointers (e.g. eax = 0x41414141), then enhance
    # the only element there is.
    if len(chain) == 1:
        # Note the "attempt_dereference" argument, which is set to False.
        # In general, this function assumes that the caller has manually fully dereferenced the input list of pointers.
        # If the only value in the list is a pointer, the function assumes this is purposeful and that that pointer cannot be dereferenced.
        # This is because the code that generated the list determined that we cannot safely reason about the dereferenced value at the current program state.
        # This case only applies to lists of length one, because if the list has more than one value, we already know
        # that the second to last value, chain[-2], can be safely dereferenced - how else would chain[-1] exist?
        # In other case where chain[-1] is not a pointer, the argument has no effect.
        enhanced = pwndbg.enhance.enhance(
            chain[-1],
            code=code,
            attempt_dereference=False,
            enhance_string_len=enhance_string_len,
        )
    # We want to enhance the last pointer value. If an offset was used
    # chain failed at that offset, so display that offset.
    elif len(chain) < limit + 1:
        enhanced = pwndbg.enhance.enhance(
            chain[-2] + offset,
            code=code,
            safe_linking=safe_linking,
            enhance_string_len=enhance_string_len,
        )

    else:
        enhanced = c.contiguous_marker(f"{config_contiguous}")

    if len(chain) == 1:
        return enhanced

    return arrow_right.join(rest) + arrow_left + enhanced
