from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.arch
import pwndbg.chain
import pwndbg.commands
import pwndbg.regs
import pwndbg.stack
import pwndbg.vmmap


@pwndbg.commands.ArgparsedCommand('Print out the stack addresses that contain return addresses.')
@pwndbg.commands.OnlyWhenRunning
def retaddr():
    for sp in pwndbg.stack.yield_retaddrs():
        print(pwndbg.chain.format(sp))
