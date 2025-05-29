from __future__ import annotations

from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg import MemoryMap

pwndbg.config.add_param(
    "vmmap-prefer-relpaths",
    True,
    "show relative paths by default in vmmap",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
)


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


def find_kbase(pages) -> int | None:
    arch_name = pwndbg.aglib.arch.name

    address = 0

    if arch_name == "x86-64":
        address = pwndbg.aglib.kernel.get_idt_entries()[0].offset
    elif arch_name == "aarch64":
        address = pwndbg.aglib.regs.vbar
    else:
        return None

    mappings = pages
    for mapping in mappings:
        # TODO: Check alignment

        # only search in kernel mappings:
        # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
        if mapping.vaddr & (0xFFFF << 48) == 0:
            continue

        if not mapping.execute:
            continue

        if address in mapping:
            return mapping.vaddr

    return None


@pwndbg.lib.cache.cache_until("start")
def kbase():
    pages = get()
    return find_kbase(pages)
