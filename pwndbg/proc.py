#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides values which would be available from /proc which
are not fulfilled by other modules.
"""
import sys
import functools
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

    @property
    def exe(self):
        auxv = pwndbg.auxv.get()

    def OnlyWhenRunning(self, func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            if self.alive:
                return func(*a, **kw)
        return wrapper

# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, '')
