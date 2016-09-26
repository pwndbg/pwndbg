#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Describes the standard Linux glibc/eglibc link_map, and
allows enumeration of loaded modules under qemu-user where
/proc/X/maps may lie or be unavialable.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.elf
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory


@pwndbg.events.new_objfile
@pwndbg.memoize.reset_on_objfile
def find():
    exe = pwndbg.elf.exe()

    if not exe:
        return None

    #
    # There are two places that the link_map can be.
    #
    # - DT_DEBUG
    # - DT_PLTGOT
    #
    # This code is mostly copied from my implementation in
    # pwntools/binjitsu.  See the documentation there:
    #
    # - https://github.com/binjitsu/binjitsu/blob/master/pwnlib/dynelf.py
    #
