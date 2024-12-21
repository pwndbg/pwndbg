"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""

from __future__ import annotations

import pwndbg
import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("objfile", "start")
def is_remote() -> bool:
    return pwndbg.dbg.selected_inferior().is_remote()
