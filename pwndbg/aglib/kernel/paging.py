from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg import config

ENTRYMASK = ~((1 << 12) - 1) & ((1 << 51) - 1)


@pwndbg.lib.cache.cache_until("start", "stop")
def get_memory_map_raw() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return pwndbg.aglib.kernel.vmmap.kernel_vmmap(False)


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
        # should be page aligned -- either from pt-dump or info mem

        # only search in kernel mappings:
        # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
        if mapping.vaddr & (0xFFFF << 48) == 0:
            continue

        if not mapping.execute:
            continue

        if address in mapping:
            return mapping.vaddr

    return None


@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def uses_5lvl_paging() -> bool:
    if pwndbg.aglib.kernel.has_debug_syms():
        ops: pwndbg.aglib.kernel.x86_64Ops = pwndbg.aglib.kernel.arch_ops()
        return ops.uses_5lvl_paging()
    pages = get_memory_map_raw()
    for page in pages:
        if page.start & (1 << 63) > 0:
            return page.start < (0xFFF << (4 * 13))
    return False


guess_physmap = config.add_param(
    "guess-physmap",
    False,
    "Should guess physmap base address when debug symbols are not present",
)


def physmap_base() -> int:
    if pwndbg.aglib.kernel.has_debug_syms() and pwndbg.aglib.arch.name == "x86-64":
        result = pwndbg.aglib.symbol.lookup_symbol_addr("page_offset_base")
        if pwndbg.aglib.memory.peek(result):
            result = pwndbg.aglib.memory.u64(result)
        else:
            return None
        if result is not None:
            return result
    if guess_physmap or pwndbg.aglib.arch.name == "aarch64":
        # this is mostly true
        # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
        for page in get_memory_map_raw():
            if page.start & (1 << 63) > 0:
                return page.start
    print(M.warn("physmap base cannot be determined, resort to default"))
    if uses_5lvl_paging():
        return 0xFF11000000000000
    return 0xFFFF888000000000


@pwndbg.lib.cache.cache_until("start")
def kbase():
    return find_kbase(get_memory_map_raw())


@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def pagewalk(target, entry=None) -> List[Tuple[int | None, int | None]]:
    level = 4
    if uses_5lvl_paging():
        level = 5
    base = physmap_base()
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
