#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import collections
import copy
import functools
import sys

import gdb

import pwndbg.events

debug = False

class memoize(object):
    caching = True

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)
        functools.update_wrapper(self, func)

    def __call__(self, *args, **kwargs):
        how = None

        if not isinstance(args, collections.Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            how   = "Not memoizeable!"
            value = self.func(*args)

        if self.caching and args in self.cache:
            how   = "Cached"
            value = self.cache[args]

        else:
            how   = "Executed"
            value = self.func(*args, **kwargs)
            self.cache[args] = value

            if isinstance(value, list):
                print("Shouldnt cache mutable types! %r" % self.func.__name__)

        if debug:
            print("%s: %s(%r)" % (how, self, args))
            print(".... %r" % (value,))
        return value

    def __repr__(self):
        funcname = self.func.__module__ + '.' + self.func.__name__
        return "<%s-memoized function %s>" % (self.kind, funcname)

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)

    def clear(self):
        if debug:
            print("Clearing %s %r" % (self, self.cache))
        self.cache.clear()



class reset_on_stop(memoize):
    caches = []
    kind   = 'stop'

    @staticmethod
    @pwndbg.events.stop
    @pwndbg.events.mem_changed
    @pwndbg.events.reg_changed
    def __reset_on_stop():
        for obj in reset_on_stop.caches:
            obj.cache.clear()

    _reset = __reset_on_stop

class reset_on_exit(memoize):
    caches = []
    kind   = 'exit'

    @staticmethod
    @pwndbg.events.exit
    def __reset_on_exit():
        for obj in reset_on_exit.caches:
            obj.clear()

    _reset = __reset_on_exit

class reset_on_objfile(memoize):
    caches = []
    kind   = 'objfile'

    @staticmethod
    @pwndbg.events.new_objfile
    def __reset_on_objfile():
        for obj in reset_on_objfile.caches:
            obj.clear()

    _reset = __reset_on_objfile

class reset_on_start(memoize):
    caches = []
    kind   = 'start'

    @staticmethod
    @pwndbg.events.stop
    @pwndbg.events.start
    def __reset_on_start():
        for obj in reset_on_start.caches:
            obj.clear()

    _reset = __reset_on_start

class reset_on_cont(memoize):
    caches = []
    kind   = 'cont'

    @staticmethod
    @pwndbg.events.cont
    def __reset_on_cont():
        for obj in reset_on_cont.caches:
            obj.clear()

    _reset = __reset_on_cont

class while_running(memoize):
    caches = []
    kind   = 'running'
    caching = False

    @staticmethod
    @pwndbg.events.start
    def __start_caching():
        while_running.caching = True

    @staticmethod
    @pwndbg.events.exit
    def __reset_while_running():
        for obj in while_running.caches:
            obj.clear()
        while_running.caching = False

    _reset = __reset_while_running


def reset():
    reset_on_stop._reset()
    reset_on_exit._reset()
    reset_on_objfile._reset()
    reset_on_start._reset()
    reset_on_cont._reset()
    while_running._reset()
