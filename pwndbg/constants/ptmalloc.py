#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import platform

import gdb

import pwndbg.arch

# Heap flags
PREV_INUSE      = 1
IS_MMAPPED      = 2
NON_MAIN_ARENA  = 4
SIZE_BITS       = ( PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA )

# Constants and macros taken from glibc malloc.c
MIN_CHUNK_SIZE      = pwndbg.arch.ptrsize * 4
MALLOC_ALLIGNMENT   = pwndbg.arch.ptrsize * 2

NBINS               = 128
NSMALLBINS          = 64
SMALLBIN_WIDTH      = MALLOC_ALLIGNMENT
SMALLBIN_CORRECTION = 1 if MALLOC_ALLIGNMENT > pwndbg.arch.ptrsize * 2 else 0

MIN_SMALL_SIZE      = MIN_CHUNK_SIZE
MIN_LARGE_SIZE      = (NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH
