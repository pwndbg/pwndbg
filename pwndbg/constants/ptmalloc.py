#!/usr/bin/env python
# -*- coding: utf-8 -*-

import platform

import gdb

import pwndbg.arch

# Heap flags
PREV_INUSE      = 1
IS_MMAPPED      = 2
NON_MAIN_ARENA  = 4
SIZE_BITS       = ( PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA )

NBINS           = 128
NSMALLBINS      = 64
