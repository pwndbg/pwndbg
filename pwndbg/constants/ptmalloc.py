#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import platform

# Heap flags
PREV_INUSE      = 1
IS_MMAPPED      = 2
NON_MAIN_ARENA  = 4
SIZE_BITS       = ( PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA )

# Use this instead of pwndbg.typeinfo, typeinfo will fail is
# glibc-dbg is not installed
def get_arch():
    maintenance = gdb.execute('maintenance info sections ?', to_string=True)
    return maintenance.strip().split()[-1:]

try:
    _machine = get_arch()[0]
except IndexError:
    _machine = ""

if "elf64" in _machine:
    SIZE_SZ = 8
elif "elf32" in _machine:
    SIZE_SZ = 4
else:
    SIZE_SZ = 0

# Constants taken from glibc mallo.c
MIN_CHUNK_SIZE      = SIZE_SZ * 4
MALLOC_ALLIGNMENT   = SIZE_SZ * 2

NBINS               = 128
NSMALLBINS          = 64
SMALLBIN_WIDTH      = MALLOC_ALLIGNMENT
SMALLBIN_CORRECTION = 1 if MALLOC_ALLIGNMENT > SIZE_SZ * 2 else 0

MIN_SMALL_SIZE      = MIN_CHUNK_SIZE
MIN_LARGE_SIZE      = (NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH

# Offset from the base of main_arena to the first smallbin
SMALLBIN_BASE_OFFSET = {4: 56, 8: 104}

"""
    Smallbins (Bins for sizes < 128 * SIZE_SZ [512 on 32 bin 1024 on 64 bit])
    are spaces 2 * SIZE_SZ bytes apart

    Large bins are approximately logorithmaclly spaces with a bit of slop
    to the actually numbers between spacing for the sake of speed.

"""

spaces_table_32 = [
                   None, # there is no index 0
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,
                   8, 8, 8, 8, 8, 8, 8, 8,

                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,

                   512, 512, 512, 512, 512, 512, 512, 512,
                   512, 512, 512, 512, 512, 512, 512, 512,

                   1536, 4096, 4096, 4096, 4096, 4096, 4096, 4096,

                   24576, 32768, 32768, 32768,

                   98304, 262144,

                   3670016
                  ]

spaces_table_64 = [
                   None, # there is no index 0
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,
                   16, 16, 16, 16, 16, 16, 16, 16,

                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,
                   64, 64, 64, 64, 64, 64, 64, 64,

                   64, 448, 512, 512, 512, 512, 512, 512,
                   512, 512, 512, 512, 512, 512, 512, 512,

                   1536, 4096, 4096, 4096, 4096, 4096, 4096, 4096,

                   24576, 32768, 32768, 32768,

                   98304, 262144,

                   3670016
                  ]

SPACES_TABLE = {4: spaces_table_32, 8: spaces_table_64}
