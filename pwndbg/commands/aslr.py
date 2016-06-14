from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.proc
import pwndbg.vmmap

options = {'on':'off', 'off':'on'}

parser = argparse.ArgumentParser(description='Inspect or modify ASLR status')
parser.add_argument('state', nargs='?', type=str, choices=options,
                    help="Turn ASLR on or off (takes effect when target is started)")

@pwndbg.commands.ArgparsedCommand(parser)
def aslr(state=None):
    """
    Check the current ASLR status, or turn it on/off.

    Does not take effect until the program is restarted.
    """
    if state:
        gdb.execute('set disable-randomization %s' % options[state], 
                    from_tty=False, to_string=True)

        if pwndbg.proc.alive:
            print("Change will take effect when the process restarts")

    aslr = pwndbg.vmmap.check_aslr()
    status = pwndbg.color.red('OFF')

    if aslr:
        status = pwndbg.color.green('ON')

    print("ASLR is %s" % status)
