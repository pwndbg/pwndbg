#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.heap.heap
import pwndbg.symbol

current = None

heap_chain_limit = pwndbg.config.Parameter('heap-dereference-limit', 8, 'number of bins to dereference')

@pwndbg.events.new_objfile
def update():
    import pwndbg.heap.dlmalloc
    import pwndbg.heap.ptmalloc

    global current


    if pwndbg.symbol.address('ptmalloc_init'):
        current = pwndbg.heap.ptmalloc.Heap()

    else:
        # Default to ptmalloc heap for now until
        # there are more implementations
        current = pwndbg.heap.ptmalloc.Heap()
