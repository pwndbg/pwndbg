#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from collections import OrderedDict

import gdb

import pwndbg.events
import pwndbg.typeinfo
from pwndbg.color import bold
from pwndbg.color import red
from pwndbg.constants import ptmalloc

class Heap(pwndbg.heap.heap.BaseHeap):
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
        main_arena_addr = pwndbg.symbol.address('main_arena')

        if main_arena_addr is not None:
            self._main_arena = pwndbg.memory.poi(self.malloc_state, main_arena_addr)
        else:
            print(bold(red('Symbol \'main arena\' not found. Try installing libc '
                           'debugging symbols and try again.')))

        return self._main_arena


    @property
    def mp(self):
        mp_addr = pwndbg.symbol.address('mp_')

        if mp_addr is not None:
            self._mp = pwndbg.memory.poi(self.malloc_par, mp_addr)

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

    def _spaces_table(self):
        spaces_table =  [ pwndbg.arch.ptrsize * 2 ]      * 64 \
                      + [ pow(2, 6) ]                    * 32 \
                      + [ pow(2, 9) ]                    * 16 \
                      + [ pow(2, 12) ]                   * 8  \
                      + [ pow(2, 15) ]                   * 4  \
                      + [ pow(2, 18) ]                   * 2  \
                      + [ pow(2, 21) ]                   * 1

        # There is no index 0
        spaces_table = [ None ] + spaces_table

        # Fix up the slop in bin spacing (part of libc - they made
        # the trade off of some slop for speed)
        # https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1356
        if pwndbg.arch.ptrsize == 8:
            spaces_table[97] = 64
            spaces_table[98] = 448

        spaces_table[113] = 1536
        spaces_table[121] = 24576
        spaces_table[125] = 98304

        return spaces_table

    def chunk_flags(self, size):
        return ( size & ptmalloc.PREV_INUSE ,
                 size & ptmalloc.IS_MMAPPED,
                 size & ptmalloc.NON_MAIN_ARENA )


    def chunk_key_offset(self, key):
        chunk_keys = self.malloc_chunk.keys()

        try:
            return chunk_keys.index(key) * pwndbg.arch.ptrsize
        except:
            return None


    def get_arena(self, arena_addr=None):
        if arena_addr is None:
            return self.main_arena

        return pwndbg.memory.poi(self.malloc_state, arena_addr)


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

        if page is not None:
            lower = lower or page.vaddr
            return (lower, page.vaddr + page.memsz)

        return (None, None)


    def fastbins(self, arena_addr=None):
        arena        = self.get_arena(arena_addr)

        if arena is None:
            return

        fastbinsY    = arena['fastbinsY']
        fd_offset    = self.chunk_key_offset('fd')
        num_fastbins = 7
        size         = pwndbg.arch.ptrsize * 2

        result = OrderedDict()
        for i in range(num_fastbins):
            size += pwndbg.arch.ptrsize * 2
            chain = pwndbg.chain.get(int(fastbinsY[i]), offset=fd_offset)

            result[size] = chain

        return result


    def bin_at(self, index, arena_addr=None):
        """
        Modeled after glibc's bin_at function - so starts indexing from 1
        https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1394

        bin_at(1) returns the unsorted bin

        Bin 1          - Unsorted BiN
        Bin 2 to 63    - Smallbins
        Bin 64 to 126  - Largebins
        """
        index = index - 1
        arena = self.get_arena(arena_addr)

        if arena is None:
            return

        normal_bins = arena['bins']
        num_bins    = normal_bins.type.sizeof // normal_bins.type.target().sizeof

        bins_base    = int(normal_bins.address) - (pwndbg.arch.ptrsize* 2)
        current_base = bins_base + (index * pwndbg.arch.ptrsize * 2)

        front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
        fd_offset   = self.chunk_key_offset('fd')

        chain = pwndbg.chain.get(int(front), offset=fd_offset, hard_stop=current_base)
        return chain


    def unsortedbin(self, arena_addr=None):
        chain  = self.bin_at(1, arena_addr=arena_addr)
        result = OrderedDict()

        if chain is None:
            return

        result['all'] = chain

        return result


    def smallbins(self, arena_addr=None):
        size         = ptmalloc.MIN_SMALL_SIZE - (pwndbg.arch.ptrsize * 2)
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(2, 64):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        return result


    def largebins(self, arena_addr=None):
        size         = ptmalloc.MIN_LARGE_SIZE - (pwndbg.arch.ptrsize * 2)
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(64, 127):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        return result
