from __future__ import annotations

import pwndbg
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
from pwndbg.dbg import EventType


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.STOP)
def update_typeinfo() -> None:
    pwndbg.aglib.typeinfo.update()
    pwndbg.aglib.arch_mod.update()
