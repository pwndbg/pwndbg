from __future__ import print_function
import os

import gdb
import pwndbg.commands
import pwndbg.vmmap

@pwndbg.commands.Command
def rop(start=None, stop=None):
    """
    Dump ROP gadgets.

    Optionally specify an address to dump all gadgets in that memory
    area, or also specify a stop address.

    Searches executable mapped pages only.
    """
    # for page in pwndbg.vmmap.get()
    cmd = ['ROPgadget',
           '--rawArch=x86',
           '--rawMode=32',
           '--binary=dump',
           '--offset=0xdeadbeef']
    os.system(' '.join(cmd))
