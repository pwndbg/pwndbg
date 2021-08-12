#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbglib.heap.heap
import pwndbglib.symbol

current = None

heap_chain_limit = pwndbglib.config.Parameter('heap-dereference-limit', 8, 'number of bins to dereference')

@pwndbglib.events.start
def update():
    import pwndbglib.heap.ptmalloc
    global current
    current = pwndbglib.heap.ptmalloc.Heap()
