#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functionality for resolving ASCII printable strings within
the debuggee's address space.
"""
from __future__ import print_function
import string

import gdb
import pwndbg.events
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
    length  = int(message)

def get(address, maxlen = None):
    if maxlen is None:
        maxlen = length

    try:
        sz = gdb.Value(address)
        sz = sz.cast(pwndbg.typeinfo.pchar)
        sz = sz.string('ascii', 'ignore')
        sz = str(sz)
    except Exception as e:
        return None

    if not all(s in string.printable for s in sz.rstrip('\x00')):
        return None

    if len(sz) < maxlen:
    	return sz

    return sz[:maxlen] + '...'
