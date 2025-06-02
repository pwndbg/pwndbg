from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg import MemoryMap

pwndbg.config.add_param(
    "vmmap-prefer-relpaths",
    True,
    "show relative paths by default in vmmap",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
)

ENTRYMASK = ~((1 << 12) - 1) & ((1 << 51) - 1)


@pwndbg.lib.cache.cache_until("start", "stop")
def get_memory_map() -> MemoryMap:
    return pwndbg.dbg.selected_inferior().vmmap()


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return tuple(get_memory_map().ranges())


@pwndbg.lib.cache.cache_until("start", "stop")
def find(address: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)
    if address < 0:
        return None

    page = get_memory_map().lookup_page(address)

    if page is not None:
        return page

    return pwndbg.aglib.vmmap_custom.explore(address)


@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def pagewalk(target, entry=None) -> List[Tuple[int | None, int | None]]:
    level = 4
    if pwndbg.aglib.kernel.uses_5lvl_paging():
        level = 5
    base = pwndbg.aglib.kernel.physmap_base()
    if entry is None:
        entry = pwndbg.aglib.regs["cr3"]
    else:
        entry = int(pwndbg.dbg.selected_frame().evaluate_expression(entry))
    if entry > base:
        # user inputted a physmap address as pointer to pgd
        entry -= base
    result: List[Tuple[int | None, int | None]] = [(None, None)] * (level + 1)
    for i in range(level, 0, -1):
        vaddr = (entry & ENTRYMASK) + base
        if entry & (1 << 7) > 0:
            break
        shift = (i - 1) * 9 + 12
        offset = target & ((1 << shift) - 1)
        idx = (target & (0x1FF << shift)) >> shift
        entry = 0
        try:
            table = pwndbg.aglib.memory.get_typed_pointer("unsigned long", vaddr)
            entry = int(table[idx])
        except Exception as e:
            print(M.warn(f"Exception while page walking: {e}"))
            entry = 0
        if entry == 0:
            return result
        result[i] = (entry, vaddr)
    result[0] = (None, (entry & ENTRYMASK) + base + offset)
    return result


def guess_physmap_base() -> int | None:
    # this is mostly true
    # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
    for page in get():
        if page.start & (1 << 63) > 0:
            return page.start
    return None
