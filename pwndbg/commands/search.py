from __future__ import print_function

import os
import struct

import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.enhance
import pwndbg.search
import pwndbg.vmmap


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def search(value):
    for address in pwndbg.search.search(value):
        if not address:
            continue

        vmmap  = pwndbg.vmmap.find(address)
        if vmmap:
            region = os.path.basename(vmmap.objfile)
        else:
            region = '[mapped]'

        region = region.ljust(15)

        region = pwndbg.color.get(address, region)
        addr = pwndbg.color.get(address)
        display = pwndbg.enhance.enhance(address)
        print(region,addr,display)
