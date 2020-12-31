#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.heap.heap
import pwndbg.symbol

current = None

heap_chain_limit = pwndbg.config.Parameter('heap-dereference-limit', 8, 'number of bins to dereference')

@pwndbg.events.start
def update():
    import pwndbg.heap.ptmalloc
    global current
    current = pwndbg.heap.ptmalloc.Heap()
