#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Search the address space for byte patterns or pointer values.
"""
import struct

import gdb
import pwndbg.arch
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap


def search(searchfor, searchtype=None):
    value = searchfor
    size  = None

    if searchtype != 'c' and searchtype != 'xc':
        if searchfor.isdigit():
            searchfor = int(searchfor)
        elif searchfor.startswith('0x') \
        and all(c in 'xABCDEFabcdef0123456789' for c in searchfor):
            searchfor = int(searchfor, 16)

        if isinstance(searchfor, (long, int)):
            if pwndbg.arch.ptrsize == 4:
                searchfor = struct.pack('I', searchfor)
            elif pwndbg.arch.ptrsize == 8:
                searchfor = struct.pack('L', searchfor)

    elif searchtype == 'xc':
        if '\\x' in searchfor:
            searchfor = bytes.fromhex(''.join(searchfor.split('\\x')))
        elif 'x' in searchfor:
            searchfor = bytes.fromhex(''.join(searchfor.split('x')))
        else:
            searchfor = bytes.fromhex(''.join(searchfor[i:i+2]
                                          for i in range(0, len(searchfor), 2)))

    i = gdb.selected_inferior()

    maps = pwndbg.vmmap.get()
    hits = []
    for vmmap in maps:
        start = vmmap.vaddr
        end   = start + vmmap.memsz
        while True:
            # No point in searching if we can't read the memory
            if not pwndbg.memory.peek(start):
                break

            start = i.search_memory(start, end - start, searchfor)

            if start is None:
                break

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            if not pwndbg.memory.peek(start):
                break

            yield start
            start += len(searchfor)
