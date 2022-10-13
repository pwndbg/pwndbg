import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.proc
import pwndbg.gdblib.vmmap
from pwndbg.color import message

options = {"on": "off", "off": "on"}

parser = argparse.ArgumentParser(
    description="""
Check the current ASLR status, or turn it on/off.

Does not take effect until the program is restarted.
"""
)
parser.add_argument(
    "state",
    nargs="?",
    type=str,
    choices=options,
    help="Turn ASLR on or off (takes effect when target is started)",
)


@pwndbg.commands.ArgparsedCommand(parser)
def aslr(state=None):
    if state:
        gdb.execute("set disable-randomization %s" % options[state], from_tty=False, to_string=True)

        if pwndbg.gdblib.proc.alive:
            print("Change will take effect when the process restarts")

    aslr, method = pwndbg.gdblib.vmmap.check_aslr()

    if aslr is True:
        status = message.on("ON")
    elif aslr is False:
        status = message.off("OFF")
    else:
        status = message.off("???")

    print("ASLR is %s (%s)" % (status, method))
