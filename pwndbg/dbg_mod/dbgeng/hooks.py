from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch_mod
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
from pwndbg.dbg_mod import EventHandlerPriority
from pwndbg.dbg_mod import EventType


@pwndbg.dbg.event_handler(EventType.NEW_MODULE, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.START, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
@pwndbg.dbg.event_handler(EventType.STOP, EventHandlerPriority.UPDATE_ARCH_AND_TYPEINFO)
def update_arch_and_typeinfo() -> None:
    pwndbg.aglib.typeinfo.update()
    pwndbg.aglib.arch_mod.update()
