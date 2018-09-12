#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Runs a few useful commands which are available under "info".

We probably don't need this anymore.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.memoize


@pwndbg.memoize.reset_on_exit
def proc_mapping():
    try:
        return gdb.execute('info proc mapping', to_string=True)
    except gdb.error:
        return ''

@pwndbg.memoize.reset_on_exit
def auxv():
    try:
        return gdb.execute('info auxv', to_string=True)
    except gdb.error:
        return ''

@pwndbg.memoize.reset_on_stop
def files():
    try:
        return gdb.execute('info files', to_string=True)
    except gdb.error:
        return ''

@pwndbg.memoize.reset_on_stop
def line():
    try:
        return gdb.execute('info line', to_string=True)
    except gdb.error:
        return ''

@pwndbg.memoize.reset_on_stop
def rel_filepath():
    """
    Returns relative filepath of currently debugged file.

    For example if `info line` returns:
    > Line 5 of "./main.c" is at address 0x555555554641 <main> but contains no code.

    This will return just './main.c'
    """
    l = line()

    if not l:
        return ''

    start = l.index('"') + 1
    end = start + l[start+1:].index('"') + 1

    return l[start:end]
