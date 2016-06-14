#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Search the address space for byte patterns.
"""
from __future__ import print_function
from __future__ import unicode_literals

import struct

import gdb
import pwndbg.arch
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap


def search(searchfor, mapping=None, start=None, end=None, 
           executable=False, writable=False):
    value = searchfor
    size  = None

    i = gdb.selected_inferior()

    maps = pwndbg.vmmap.get()
    hits = []

    if end and start:
        maps = [m for m in maps if start <= m < end]

    if executable:
        maps = [m for m in maps if m.execute]

    if writable:
        maps = [m for m in maps if m.write]

    for vmmap in maps:
        start = vmmap.vaddr
        end   = start + vmmap.memsz

        if mapping and mapping not in vmmap.objfile:
            continue

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
