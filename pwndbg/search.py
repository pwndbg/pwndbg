#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Search the address space for byte patterns or pointer values.
"""
import struct

import gdb
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap
import pwndbg.arch


def search(searchfor):
    value = searchfor
    size  = None

    if searchfor.isdigit():
        searchfor = int(searchfor)
    elif all(c in 'xABCDEFabcdef0123456789' for c in searchfor):
        searchfor = int(searchfor, 16)

    if isinstance(searchfor, (long, int)):
        if pwndbg.arch.ptrsize == 4:
            searchfor = struct.pack('I', searchfor)
        elif pwndbg.arch.ptrsize == 8:
            searchfor = struct.pack('L', searchfor)

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
