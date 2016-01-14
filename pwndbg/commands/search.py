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
def search(searchtype, value=None):
    """
    Search memory for the specified value, provided
    either as a pointer-width integer, or a string.

    > search 0xdeadbeef
    > search "/bin/sh"
    
    To search 1234 in a character string instead of integer
    > search/c 1234
    
    To search for characters using hex values in string
    > search/xc f0f1f2f3
    > search/xc \xf0\xf1\xf2\xf3
    > search/xc \\xf0\\xf1\\xf2\\xf3
    """
    
    if value:
        searchtype = searchtype[1:]
    else:
        value, searchtype = searchtype, value
    
    hits = set()

    for address in pwndbg.search.search(value, searchtype):
        if not address:
            continue

        if address in hits:
            continue

        hits.add(address)

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

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def searchmem(searchtype, value=None):
    """
    Search memory for the specified value, provided
    either as a pointer-width integer, or a string.

    > search 0xdeadbeef
    > search "/bin/sh"
    
    To search 1234 in a character string instead of integer
    > search/c 1234
    
    To search for characters using hex values in string
    > search/xc f0f1f2f3
    > search/xc \xf0\xf1\xf2\xf3
    > search/xc \\xf0\\xf1\\xf2\\xf3
    """
    if value:
        return search(searchtype, value)
    else:
        return search(searchtype)
