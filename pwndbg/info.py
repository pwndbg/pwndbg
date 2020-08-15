#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Runs a few useful commands which are available under "info".

We probably don't need this anymore.
"""

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
