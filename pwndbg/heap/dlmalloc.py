#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gdb

import pwndbg.events
import pwndbg.typeinfo


class Heap(pwndbg.heap.heap.BaseHeap):
    pass
