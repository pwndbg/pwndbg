#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.events
import pwndbg.typeinfo

class Heap(pwndbg.heap.heap.Heap):

    def __init__(self):
        # Global ptmalloc objects
        self._main_arena    = None
        self._mp            = None

        # Symbols and types
        self._malloc_chunk  = None
        self._malloc_state  = None
        self._mallinfo      = None
        self._malloc_par    = None

    @property
    def main_arena(self):
        if not self._main_arena:
            main_arena_symbol = gdb.lookup_symbol('main_arena')[0]

            if main_arena_symbol is not None:
                self._main_arena = main_arena_symbol.value()

        return self._main_arena

    @property
    def mp(self):
        if not self._mp:
            mp_symbol = gdb.lookup_symbol('mp_')[0]

            if mp_symbol is not None:
                self._mp = mp_symbol.value()

        return self._mp

    @property
    def malloc_chunk(self):
        if not self._malloc_chunk:
            self._malloc_chunk = pwndbg.typeinfo.load('struct malloc_chunk')
        return self._malloc_chunk

    @property
    def malloc_state(self):
        if not self._malloc_state:
            self._malloc_state = pwndbg.typeinfo.load('struct malloc_state')
        return self._malloc_state

    @property
    def mallinfo(self):
        if not self._mallinfo:
            self._mallinfo = pwndbg.typeinfo.load('struct mallinfo')
        return self._mallinfo

    @property
    def malloc_par(self):
        if not self._malloc_par:
            self._malloc_par = pwndbg.typeinfo.load('struct malloc_par')
        return self._malloc_par

    def get_arena(self, arena_addr=None):
        if arena_addr is None:
            return self.main_arena

        return gdb.Value(addr).cast(self.malloc_state.pointer()).dereference()

    def get_bounds(self):
        """
        Finds the heap bounds by using mp_ structure's sbrk_base property
        and falls back to using /proc/self/maps (vmmap) which can be wrong
        when .bss is very large
        """
        lower, upper = None, None

        try:
            lower = int(self.mp['sbrk_base'])
        except:
            lower = None

        page = None
        for m in pwndbg.vmmap.get():
            if m.objfile == '[heap]':
                page = m
                break

        if page != None:
            lower = lower or page.vaddr
            return (lower, page.vaddr + page.memsz)

        return (None, None)
