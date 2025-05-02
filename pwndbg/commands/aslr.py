from __future__ import annotations

import argparse
from typing import Tuple

import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.dbg
from pwndbg.color import message
from pwndbg.commands import CommandCategory

if pwndbg.dbg.is_gdblib_available():
    import gdb


def check_aslr() -> Tuple[bool | None, str]:
    """
    Detects the ASLR status. Returns True, False or None.

    None is returned when we can't detect ASLR.
    """
    # QEMU does not support this concept.
    if pwndbg.aglib.qemu.is_qemu():
        return None, "Could not detect ASLR on QEMU targets"

    # Systemwide ASLR is disabled
    try:
        data = pwndbg.aglib.file.get("/proc/sys/kernel/randomize_va_space")
        if b"0" in data:
            return False, "kernel.randomize_va_space == 0"
    except Exception:
        print("Could not check ASLR: can't read randomize_va_space")

    # Check the personality of the process
    if pwndbg.aglib.proc.alive:
        try:
            data = pwndbg.aglib.file.get("/proc/%i/personality" % pwndbg.aglib.proc.tid)
            personality = int(data, 16)
            return (personality & 0x40000 == 0), "read status from process' personality"
        except Exception:
            print("Could not check ASLR: can't read process' personality")

    if not pwndbg.dbg.is_gdblib_available():
        return None, "Could not detect ASLR on LLDB"

    # Just go with whatever GDB says it did.
    #
    # This should usually be identical to the above, but we may not have
    # access to procfs.
    output = gdb.execute("show disable-randomization", to_string=True)
    return ("is off." in output), "show disable-randomization"


options = {"on": "off", "off": "on"}

parser = argparse.ArgumentParser(
    description="""
Check the current ASLR status, or turn it on/off.

Does not take effect until the program is restarted.
""",
)
parser.add_argument(
    "state",
    nargs="?",
    type=str,
    choices=options,
    help="Turn ASLR on or off (takes effect when target is started)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
def aslr(state=None) -> None:
    if state:
        if pwndbg.dbg.is_gdblib_available():
            gdb.execute(
                f"set disable-randomization {options[state]}", from_tty=False, to_string=True
            )

            if pwndbg.aglib.proc.alive:
                print("Change will take effect when the process restarts")
        else:
            # TODO: lldb settings set target.disable-aslr false
            print(
                "Please use command 'settings set target.disable-aslr true/false', autocommand not supported yet"
            )

    aslr, method = check_aslr()

    if aslr is True:
        status = message.on("ON")
    elif aslr is False:
        status = message.off("OFF")
    else:
        status = message.off("???")

    print(f"ASLR is {status} ({method})")
