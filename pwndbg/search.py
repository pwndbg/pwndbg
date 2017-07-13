#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Search the address space for byte patterns.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import struct

import gdb

import pwndbg.arch
import pwndbg.memory
import pwndbg.typeinfo
import pwndbg.vmmap


def search(searchfor, mappings=None, start=None, end=None, 
           executable=False, writable=False):
    """Search inferior memory for a byte sequence.

    Arguments:
        searchfor(bytes): Byte sequence to find
        mappings(list): List of pwndbg.memory.Page objects to search
            By default, uses all available mappings.
        start(int): First address to search, inclusive.
        end(int): Last address to search, exclusive.
        executable(bool): Restrict search to executable pages
        writable(bool): Restrict search to writable pages

    Yields:
        An iterator on the address matches
    """
    value = searchfor
    size  = None

    i = gdb.selected_inferior()

    maps = mappings or pwndbg.vmmap.get()
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

        while True:
            # No point in searching if we can't read the memory
            if not pwndbg.memory.peek(start):
                break

            length = end - start
            if length <= 0:
                break

            start = i.search_memory(start, length, searchfor)

            if start is None:
                break

            # For some reason, search_memory will return a positive hit
            # when it's unable to read memory.
            if not pwndbg.memory.peek(start):
                break

            yield start
            start += len(searchfor)
