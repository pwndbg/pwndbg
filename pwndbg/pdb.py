#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This module serves as utility for the developers to get pdb debugging session right, whenever standard:
    import pdb; pdb.set_trace()
Can't do its job properly (that happens often as gdb does some magic with stdout/stderr).

Thanks to Dmoreno: http://stackoverflow.com/questions/17074177/how-to-debug-python-cli-that-takes-stdin

Usage:
    import pwndbg.pdb

Importing the module will print out pretty message on what to do next.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import signal
import stat
import sys

# If you want to use ipdb, uncomment below lines
# However, IPython support is kinda... weird
# the colored output appears in gdb window and it requires you to press enter there (e.g. for list command)
# This has to be pushed/extended to make it work properly:
#   https://github.com/gotcha/ipdb/issues/13
#try:
#    from IPython.core.debugger import Pdb
#except:
from pdb import Pdb

from pwndbg.color import bold
from pwndbg.color import green
from pwndbg.color import light_purple
from pwndbg.color import light_yellow
from pwndbg.color import red


fifo_stdin = '/tmp/pwndbg_stdin'
fifo_stdout = '/tmp/pwndbg_stdout'

print(red('~~~ pwndbg debug session launched ~~~'))
print(green('Creating fifos:'))


def spawn_fifo(fifo_path):
    # see https://docs.python.org/3/library/stat.html#S_ISFIFO
    if not os.path.exists(fifo_path):
        os.mkfifo(fifo_path)
        print(green('    %s fifo created' % fifo_path))

    elif stat.S_ISFIFO(os.stat(fifo_path).st_mode):
        print(light_yellow('    %s fifo already exists' % fifo_path))

    else:
        print(red('    %s already exists and is not a fifo, aborting pdb session'))
        return False

    return True


def signal_handler(*_):
    print(red('Killing pwndbg debug session, bye!'))
    sys.exit(0)

if spawn_fifo(fifo_stdin) and spawn_fifo(fifo_stdout):
    msgs = (
        'Launch another console and fire this two lines:',
        'cat %s &' % fifo_stdout,
        'cat > % s' % fifo_stdin
    )

    print('\n'.join(map(green, msgs)))

    warn = lambda string: bold(light_purple(string))

    print(warn('! NOTE: To exit gdb press CTRL+C'))
    print(warn('! NOTE: Closing the terminal may leave gdb open!'))

    signal.signal(signal.SIGINT, signal_handler)

    # can't use with statement here for opening fifos because pdb
    # raises `ValueError: I/O operation on closed file.`
    pdb_session = Pdb(stdin=open(fifo_stdin, 'r'), stdout=open(fifo_stdout, 'w'))
    pdb_session.set_trace()
