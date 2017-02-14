#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functionality for resolving ASCII printable strings within
the debuggee's address space.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import string

import gdb

import pwndbg.events
import pwndbg.memory
import pwndbg.typeinfo

length = 15

@pwndbg.events.stop
def update_length():
    r"""
    Unfortunately there's not a better way to get at this info.

    >>> gdb.execute('show print elements', from_tty=False, to_string=True)
    'Limit on string chars or array elements to print is 21.\n'
    """
    global length
    message = gdb.execute('show print elements', from_tty=False, to_string=True)
    message = message.split()[-1]
    message = message.strip('.')
    if message == 'unlimited':
        length = 0
    else:
        length = int(message)

def get(address, maxlen = None):
    if maxlen is None:
        maxlen = length

    try:
        sz = pwndbg.memory.string(address, maxlen)
        sz = sz.decode('latin-1', 'replace')

        if not sz or not all(s in string.printable for s in sz):
            return None
    except Exception as e:
        return None

    if len(sz) < maxlen or not maxlen:
        return sz

    return sz[:maxlen] + '...'
