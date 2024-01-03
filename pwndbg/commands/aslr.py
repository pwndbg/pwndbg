from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.proc
import pwndbg.gdblib.vmmap
from pwndbg.color import message
from pwndbg.commands import CommandCategory

options = {"on": "off", "off": "on"}

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
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


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
def aslr(state=None) -> None:
    if state:
        gdb.execute(f"set disable-randomization {options[state]}", from_tty=False, to_string=True)

        if pwndbg.gdblib.proc.alive:
            print("Change will take effect when the process restarts")

    aslr, method = pwndbg.gdblib.vmmap.check_aslr()

    if aslr is True:
        status = message.on("ON")
    elif aslr is False:
        status = message.off("OFF")
    else:
        status = message.off("???")

    print(f"ASLR is {status} ({method})")
