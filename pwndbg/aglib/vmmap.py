from __future__ import annotations

from typing import Tuple

import pwndbg
import pwndbg.lib.cache
import pwndbg.lib.memory

if pwndbg.dbg.is_gdblib_available():
    # The code in pwndbg.gdblib.vmmap does _so much_ more than just getting the
    # entries of the vmmap. We'll probably have to port it to run on top of the
    # Debugger-agnostic API, rather than embed its functionality inside it. When
    # that happens, this file will become that port. For now, we just fall back
    # on gdblib if possible, and expose weaker versions of these functions when
    # it's not available.
    #
    # TODO: Port `pwndbg.gdblib.vmmap` to `aglib`.
    import pwndbg.gdblib.vmmap


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    if pwndbg.dbg.is_gdblib_available():
        return pwndbg.gdblib.vmmap.get()

    return tuple(pwndbg.dbg.selected_inferior().vmmap().ranges())


@pwndbg.lib.cache.cache_until("start", "stop")
def find(address: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)

    for page in get():
        if address in page:
            return page

    if pwndbg.dbg.is_gdblib_available():
        return pwndbg.gdblib.vmmap.explore(address)
    return None
