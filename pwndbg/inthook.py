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

import enum
import os

import gdb
import six
from future.utils import with_metaclass

import pwndbg.typeinfo

if six.PY2:
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

        elif isinstance(value, gdb.Symbol):
            symbol = value
            value = symbol.value()
            if symbol.is_function:
                value = value.cast(pwndbg.typeinfo.ulong)

        elif not isinstance(value, (six.string_types, six.integer_types)) \
                or isinstance(cls, enum.EnumMeta):
            # without check for EnumMeta math operations with enums were failing e.g.:
            #     pwndbg> py import re; flags = 1 | re.MULTILINE
            return _int.__new__(cls, value, *a, **kw)

        return _int(_int(value, *a, **kw))

# Do not hook 'int' if we are just generating documentation
if os.environ.get('SPHINX', None) is None:
    builtins.int = xint
    globals()['int'] = xint
    if six.PY3:
        builtins.long = xint
        globals()['long'] = xint
