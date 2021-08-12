#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbglib.commands
import pwndbglib.proc
import pwndbglib.vmmap
from pwndbglib.color import message

options = {'on':'off', 'off':'on'}

parser = argparse.ArgumentParser(description='''
Check the current ASLR status, or turn it on/off.

Does not take effect until the program is restarted.
''')
parser.add_argument('state', nargs='?', type=str, choices=options,
                    help="Turn ASLR on or off (takes effect when target is started)")

@pwndbglib.commands.ArgparsedCommand(parser)
def aslr(state=None):
    if state:
        gdb.execute('set disable-randomization %s' % options[state], 
                    from_tty=False, to_string=True)

        if pwndbglib.proc.alive:
            print("Change will take effect when the process restarts")

    aslr, method = pwndbglib.vmmap.check_aslr()
    status = message.off('OFF')

    if aslr:
        status = message.on('ON')

    print("ASLR is %s (%s)" % (status, method))
