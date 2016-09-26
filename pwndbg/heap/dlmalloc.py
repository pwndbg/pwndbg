#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.events
import pwndbg.typeinfo

malloc_chunk = None
malloc_state = None
mallinfo     = None

@pwndbg.events.new_objfile
def update():
  malloc_chunk = gdb.lookup_type('struct malloc_chunk')
  malloc_state = gdb.lookup_type('struct malloc_state')
  mallinfo = gdb.lookup_type('struct mallinfo')
