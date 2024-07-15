from __future__ import annotations

import gdb

import pwndbg
import pwndbg.gdblib.file
import pwndbg.gdblib.qemu
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.dbg import EventType


@pwndbg.lib.cache.cache_until("start", "exit")
def is_android() -> bool:
    if pwndbg.gdblib.qemu.is_qemu():
        return False

    try:
        if pwndbg.gdblib.file.get("/system/etc/hosts"):
            return True
    except OSError:
        pass

    return False


@pwndbg.dbg.event_handler(EventType.START)
def sysroot() -> None:
    cmd = "set sysroot remote:/"
    if is_android():
        if gdb.parameter("sysroot") == "target:":
            gdb.execute(cmd)
        else:
            print(message.notice("sysroot is already set, skipping %r" % cmd))
