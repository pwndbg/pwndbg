#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.heap.heap
import pwndbg.symbol

current_heap = None

@pwndbg.events.new_objfile
def update():
    import pwndbg.heap.dlmalloc
    import pwndbg.heap.ptmalloc

    global current_heap


    if pwndbg.symbol.address('ptmalloc_init'):
        current_heap = pwndbg.heap.ptmalloc.Heap()

    else:
        # Default to ptmalloc heap for now until
        # there are more implementations
        current_heap = pwndbg.heap.ptmalloc.Heap()

def get_heap():
    return current_heap
