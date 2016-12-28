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

NBINS           = 128
NSMALLBINS      = 64
