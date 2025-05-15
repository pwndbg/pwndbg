from __future__ import annotations

import pwndbg
import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("start", "objfile")
def is_baremetal() -> bool:
    """
    This function should be called before stray memory dereferences to protect against the following situations:

    1. On embedded systems, it's not uncommon for MMIO regions to exist where memory reads might mutate the hardware/process state.
    2. Paging doesn't exist, so all memory is "valid" (and often initialized to zero) - this makes everything value appear to be a pointer.


    As such, we disable dereferencing by default for bare metal targets.

    See more discussion here: https://github.com/pwndbg/pwndbg/pull/385
    """

    # TODO: use a better detection method
    return not pwndbg.dbg.selected_inferior().is_linux()
