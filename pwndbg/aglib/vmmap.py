from __future__ import annotations

from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.lib.cache
import pwndbg.lib.memory

pwndbg.config.add_param(
    "vmmap-prefer-relpaths",
    True,
    "show relative paths by default in vmmap",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
)


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return tuple(pwndbg.dbg.selected_inferior().vmmap().ranges())


@pwndbg.lib.cache.cache_until("start", "stop")
def find(address: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)
    if address < 0:
        return None

    for page in get():
        if address in page:
            return page

    return pwndbg.aglib.vmmap_custom.explore(address)
