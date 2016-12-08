#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
from collections import OrderedDict

import pwndbg.events
import pwndbg.typeinfo
from pwndbg.constants.ptmalloc import *


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
        from pwndbg.color import bold
        from pwndbg.color import red

        if not self._main_arena:
            main_arena_symbol = gdb.lookup_symbol('main_arena')[0]

            if main_arena_symbol is not None:
                self._main_arena = main_arena_symbol.value()
            else:
                print(bold(red('Symbol \'main arena\' not found. Try installing libc '
                          'debugging symbols and try again.')))

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

    def chunk_flags(self, size):
        return ( size & PREV_INUSE, size & IS_MMAPPED, size & NON_MAIN_ARENA )

    def get_arena(self, arena_addr=None):
        if arena_addr is None:
            return self.main_arena

        return gdb.Value(arena_addr).cast(self.malloc_state.pointer()).dereference()

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

    def fastbins(self, arena_addr=None):
        arena        = self.get_arena(arena_addr)

        if arena == None:
            return

        fastbinsY    = arena['fastbinsY']
        fd_offset    = self.malloc_chunk.keys().index('fd') * SIZE_SZ
        num_fastbins = 7
        size         = SIZE_SZ * 2

        result = OrderedDict()
        for i in range(num_fastbins):
            size += SIZE_SZ * 2
            chain = pwndbg.chain.get(int(fastbinsY[i]), offset=fd_offset)

            result[size] = chain

        return result

    def bin_at(self, index, arena_addr=None):
        """
        Modeled after glibc's bin_at function - so starts indexing from 1

        bin_at(1) returns the unsorted bin

        Bin 1          - Unsorted Bin
        Bin 2 to 63    - Smallbins
        Bin 64 to 126  - Largebins
        """
        assert( index > 0 and index < NBINS )
        index = index - 1

        arena       = self.get_arena(arena_addr)

        if arena == None:
            return

        normal_bins = arena['bins']
        num_bins    = normal_bins.type.sizeof // normal_bins.type.target().sizeof

        bins_base    = int(normal_bins.address) - (SIZE_SZ * 2)
        current_base = bins_base + (index * SIZE_SZ * 2)

        front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
        fd_offset   = self.malloc_chunk.keys().index('fd') * SIZE_SZ

        chain = pwndbg.chain.get(int(front), offset=fd_offset, hard_stop=current_base)
        return chain

    def unsortedbin(self, arena_addr=None):
        result = OrderedDict()
        chain = self.bin_at(1, arena_addr=arena_addr)

        if chain == None:
            return

        result['all'] = chain

        return result

    def smallbins(self, arena_addr=None):
        size   = MIN_SMALL_SIZE - (SIZE_SZ * 2)
        result = OrderedDict()

        for index in range(2, 64):
            size += SPACES_TABLE[SIZE_SZ][index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain == None:
                return

            result[size] = chain

        return result

    def largebins(self, arena_addr=None):
        size    = MIN_LARGE_SIZE - (SIZE_SZ * 2)
        result  = OrderedDict()

        for index in range(64, 127):
            size += SPACES_TABLE[SIZE_SZ][index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain == None:
                return

            result[size] = chain

        return result

    def format_bin(self, bins, verbose=False):
        from pwndbg.color import bold

        result = []
        for size in bins:
            chain = bins[size]

            if not verbose and chain == [0]:
                continue

            formatted_chain = pwndbg.chain.format(chain)
            result.append((bold(size) + ': ').ljust(13) + formatted_chain)

        if not result:
            result.append(bold('empty'))

        return result
