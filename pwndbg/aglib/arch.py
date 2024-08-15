from __future__ import annotations

import pwndbg

# We will optimize this module in the future, by having it work in the same
# way the `gdblib` version of it works, and that will come at the same
# time this module gets expanded to have the full feature set of its `gdlib`
# coutnerpart. For now, though, this should be good enough.


def __getattr__(name):
    if name == "endian":
        return pwndbg.dbg.selected_inferior().arch().endian
    elif name == "ptrsize":
        return pwndbg.dbg.selected_inferior().arch().ptrsize
