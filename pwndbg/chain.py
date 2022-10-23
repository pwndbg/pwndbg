import gdb

import pwndbg.color.memory as M
import pwndbg.color.theme as theme
import pwndbg.enhance
import pwndbg.gdblib.abi
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec

LIMIT = pwndbg.gdblib.config.add_param(
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
    address,
    limit=LIMIT,
    offset=0,
    hard_stop=None,
    hard_end=0,
    include_start=True,
    safe_linking=False,
):
    """
    Recursively dereferences an address. For bare metal, it will stop when the address is not in any of vmmap pages to avoid redundant dereference.

    Arguments:
        address(int): the first address to begin dereferencing
        limit(int): number of valid pointers
        offset(int): offset into the address to get the next pointer
        hard_stop(int): address to stop at
        hard_end: value to append when hard_stop is reached
        include_start(bool): whether to include starting address or not
        safe_linking(bool): whether this chain use safe-linking

    Returns:
        A list representing pointers of each ```address``` and reference
    """
    limit = int(limit)

    result = [address] if include_start else []
    for i in range(limit):
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
            if not pwndbg.gdblib.abi.linux and not pwndbg.gdblib.vmmap.find(address):
                break

            next_address = int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, address))
            address = next_address ^ ((address >> 12) if safe_linking else 0)
            address &= pwndbg.gdblib.arch.ptrmask
            result.append(address)
        except gdb.MemoryError:
            break

    return result


config_arrow_left = theme.add_param("chain-arrow-left", "◂—", "left arrow of chain formatting")
config_arrow_right = theme.add_param("chain-arrow-right", "—▸", "right arrow of chain formatting")
config_contiguous = theme.add_param(
    "chain-contiguous-marker", "...", "contiguous marker of chain formatting"
)


def format(value, limit=LIMIT, code=True, offset=0, hard_stop=None, hard_end=0, safe_linking=False):
    """
    Recursively dereferences an address into string representation, or convert the list representation
    of address dereferences into string representation.

    Arguments:
        value(int|list): Either the starting address to be sent to get, or the result of get (a list)
        limit(int): Number of valid pointers
        code(bool): Hint that indicates the value may be an instruction
        offset(int): Offset into the address to get the next pointer
        hard_stop(int): Value to stop on
        hard_end: Value to append when hard_stop is reached: null, value of hard stop, a string.
        safe_linking(bool): whether this chain use safe-linking

    Returns:
        A string representing pointers of each address and reference
        Strings format: 0x0804a10 —▸ 0x08061000 ◂— 0x41414141
    """
    limit = int(limit)

    # Allow results from get function to be passed to format
    if isinstance(value, list):
        chain = value
    else:
        chain = get(value, limit, offset, hard_stop, hard_end, safe_linking=safe_linking)

    arrow_left = c.arrow(" %s " % config_arrow_left)
    arrow_right = c.arrow(" %s " % config_arrow_right)

    # Colorize the chain
    rest = []
    for link in chain:
        symbol = pwndbg.gdblib.symbol.get(link) or None
        if symbol:
            symbol = "%#x (%s)" % (link, symbol)
        rest.append(M.get(link, symbol))

    # If the dereference limit is zero, skip any enhancements.
    if limit == 0:
        return rest[0]
    # Otherwise replace last element with the enhanced information.
    rest = rest[:-1]

    # Enhance the last entry
    # If there are no pointers (e.g. eax = 0x41414141), then enhance
    # the only element there is.
    if len(chain) == 1:
        enhanced = pwndbg.enhance.enhance(chain[-1], code=code)

    # Otherwise, the last element in the chain is the non-pointer value.
    # We want to enhance the last pointer value. If an offset was used
    # chain failed at that offset, so display that offset.
    elif len(chain) < limit + 1:
        enhanced = pwndbg.enhance.enhance(chain[-2] + offset, code=code, safe_linking=safe_linking)

    else:
        enhanced = c.contiguous_marker("%s" % config_contiguous)

    if len(chain) == 1:
        return enhanced

    return arrow_right.join(rest) + arrow_left + enhanced
