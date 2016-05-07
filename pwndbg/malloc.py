#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Describes the EGLIBC heap mechanisms.

Work-in-progress.
"""
from __future__ import print_function
import pwndbg.arch
import pwndbg.events

did_warn_once = False
malloc_chunk  = None

@pwndbg.events.new_objfile
def load_malloc_chunk():
	malloc_chunk = None


def chunk2mem(p):
    "conversion from malloc header to user pointer"
    return p + (2*pwndbg.arch.ptrsize)

def mem2chunk(mem):
    "conversion from user pointer to malloc header"
    return mem - (2*pwndbg.arch.ptrsize)
