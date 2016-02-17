from __future__ import print_function

import os
import struct

import gdb
import pwndbg.color
import pwndbg.commands
import pwndbg.enhance
import pwndbg.search
import pwndbg.vmmap


def print_search(value):
    hits = set()

    for address in pwndbg.search.search(value):
        if not address:
            continue

        if address in hits:
            continue

        hits.add(address)

        vmmap = pwndbg.vmmap.find(address)
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
def search(searchtype, value=None):
    """
    Search memory for the specified value, provided
    either as a pointer-width integer, or a string.

    > search 0xdeadbeef
    > search "/bin/sh"

    To search 1234 in a character string instead of integer
    > search/c 1234

    To search for characters using hex values in string
    > search/x f0f1f2f3
    > search/x \\xf0\\xf1\\xf2\\xf3
    > search/x \\\\xf0\\\\xf1\\\\xf2\\\\xf3
    """
    if value:
        searchtype = searchtype[1:]
    else:
        value, searchtype = searchtype, value

    if searchtype:
        if searchtype == 'c' or searchtype == 'x':
            searchtype = '/' + searchtype
            searchb(searchtype,value)
            return
        else:
            print(pwndbg.color.red("Invalid option {0}".format(searchtype)))
            return

    if value.isdigit():
        value = int(value)
    elif value.startswith('0x') \
    and all(c in 'xABCDEFabcdef0123456789' for c in value):
        value = int(value, 16)

    if isinstance(value, (long, int)):
        if pwndbg.arch.ptrsize == 4:
            value = struct.pack('I', value)
        elif pwndbg.arch.ptrsize == 8:
            value = struct.pack('L', value)

    print_search(value)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def searchmem(searchtype, searchvalue=None):
    """
    Search memory for the specified value, provided
    either as a pointer-width integer, or a string.

    > searchmem 0xdeadbeef
    > searchmem "/bin/sh"

    To search 1234 in a character string instead of integer
    > searchmem/c 1234

    To search for characters using hex values in string
    > searchmem/x f0f1f2f3
    > searchmem/x \\xf0\\xf1\\xf2\\xf3
    > searchmem/x \\\\xf0\\\\xf1\\\\xf2\\\\xf3
    """
    return search(searchtype,searchvalue)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def searchb(searchtype, value=None):
    """
    Search memory for the specified value, provided
    as a string of characters or hexadecimal values.

    > searchb 1234

    To search for characters using hex values in string
    > searchb/x f0f1f2f3
    > searchb/x \\xf0\\xf1\\xf2\\xf3
    > searchb/x \\\\xf0\\\\xf1\\\\xf2\\\\xf3
    """
    if value:
        searchtype = searchtype[1:]
    else:
        value, searchtype = searchtype, value

    if searchtype == 'x':
        if '\\x' in value:
            value = bytes.fromhex(''.join(value.split('\\x')))
        elif 'x' in value:
            value = bytes.fromhex(''.join(value.split('x')))
        else:
            value = bytes.fromhex(''.join(value[i:i+2]
                                          for i in range(0, len(value), 2)))
    print_search(value)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def searchd(value):
    """
    Searches memory for the specified value,
    provided as a pointer-width integer.

    > searchd 0xdeadbeef
    """
    return search(value)
