#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This hook is necessary for compatibility with Python2.7 versions of GDB
since they cannot directly cast to integer a gdb.Value object that is
not already an integer type.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys

import gdb
from future.utils import with_metaclass

import pwndbg.typeinfo

if sys.version_info < (3,0):
    import __builtin__ as builtins
else:
    import builtins

_int = builtins.int

# We need this class to get isinstance(7, xint) to return True
class IsAnInt(type):
    def __instancecheck__(self, other):
        return isinstance(other, _int)

class xint(with_metaclass(IsAnInt, builtins.int)):
    def __new__(cls, value, *a, **kw):
        if isinstance(value, gdb.Value):
            if pwndbg.typeinfo.is_pointer(value):
                value = value.cast(pwndbg.typeinfo.ulong)
            else:
                value = value.cast(pwndbg.typeinfo.long)
        if isinstance(value, gdb.Symbol):
            symbol = value
            value  = symbol.value()
            if symbol.is_function:
                value = value.cast(pwndbg.typeinfo.ulong)
        return _int(_int(value, *a, **kw))

# Do not hook 'int' if we are just generating documentation
if os.environ.get('SPHINX', None) is None:
    builtins.int = xint
    globals()['int'] = xint

    if sys.version_info >= (3,0):
        builtins.long = xint
        globals()['long'] = xint
