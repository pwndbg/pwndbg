#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
