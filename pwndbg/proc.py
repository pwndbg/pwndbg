#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides values which would be available from /proc which
are not fulfilled by other modules.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import sys
from types import ModuleType

import gdb

import pwndbg.memoize
import pwndbg.qemu


class module(ModuleType):
    @property
    def pid(self):
        # QEMU usermode emualtion always returns 42000 for some reason.
        # In any case, we can't use the info.
        if pwndbg.qemu.is_qemu_usermode():
            return pwndbg.qemu.pid()

        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def tid(self):
        if pwndbg.qemu.is_qemu_usermode():
            return pwndbg.qemu.pid()

        i = gdb.selected_thread()
        if i is not None:
            return i.ptid[1]

        return self.pid

    @property
    def alive(self):
        return gdb.selected_thread() is not None

    @property
    def exe(self):
        for obj in gdb.objfiles():
            if obj.filename:
                return obj.filename
            break
        if self.alive:
            auxv = pwndbg.auxv.get()
            return auxv['AT_EXECFN']
    def OnlyWhenRunning(self, func):
        @functools.wraps(func)
        def wrapper(*a, **kw):
            if self.alive:
                return func(*a, **kw)
        return wrapper

# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, '')
