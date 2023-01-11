import gdb

import pwndbg.gdblib.events
import pwndbg.gdblib.file
import pwndbg.gdblib.qemu
import pwndbg.lib.memoize
from pwndbg.color import message


@pwndbg.lib.memoize.reset_on_start
@pwndbg.lib.memoize.reset_on_exit
def is_android() -> bool:
    if pwndbg.gdblib.qemu.is_qemu():
        return False

    try:
        if pwndbg.gdblib.file.get("/system/etc/hosts"):
            return True
    except OSError:
        pass

    return False


@pwndbg.gdblib.events.start
def sysroot() -> None:
    cmd = "set sysroot remote:/"
    if is_android():
        if gdb.parameter("sysroot") == "target:":
            gdb.execute(cmd)
        else:
            print(message.notice("sysroot is already set, skipping %r" % cmd))
