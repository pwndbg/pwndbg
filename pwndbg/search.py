#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Search the address space for byte patterns.
"""
from __future__ import print_function
import struct

import gdb
import pwndbg.arch
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap


def search(searchfor):
    value = searchfor
    size  = None

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
