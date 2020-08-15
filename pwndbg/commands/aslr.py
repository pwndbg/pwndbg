#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbg.commands
import pwndbg.proc
import pwndbg.vmmap
from pwndbg.color import message

options = {'on':'off', 'off':'on'}

parser = argparse.ArgumentParser(description='''
Check the current ASLR status, or turn it on/off.

Does not take effect until the program is restarted.
''')
parser.add_argument('state', nargs='?', type=str, choices=options,
                    help="Turn ASLR on or off (takes effect when target is started)")

@pwndbg.commands.ArgparsedCommand(parser)
def aslr(state=None):
    if state:
        gdb.execute('set disable-randomization %s' % options[state], 
                    from_tty=False, to_string=True)

        if pwndbg.proc.alive:
            print("Change will take effect when the process restarts")

    aslr, method = pwndbg.vmmap.check_aslr()
    status = message.off('OFF')

    if aslr:
        status = message.on('ON')

    print("ASLR is %s (%s)" % (status, method))
