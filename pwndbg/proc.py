#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides values which would be available from /proc which
are not fulfilled by other modules.
"""
import sys
from types import ModuleType

import gdb
import pwndbg.memoize


class module(ModuleType):
    @property
    def pid(self):
        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def alive(self):
        return gdb.selected_thread() is not None

    def OnlyWhenRunning(self, func):
        def wrapper(*a, **kw):
            func.__doc__
            if self.alive:
                return func(*a, **kw)
        wrapper.__name__ = func.__name__
        wrapper.__module__ = func.__module__
        wrapper.__doc__ = func.__doc__
        return wrapper

# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, '')
