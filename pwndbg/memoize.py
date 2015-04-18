#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""
from __future__ import print_function

import collections
import copy
import functools
import sys

import gdb
import pwndbg.events

debug = False

class memoize(object):
    def __call__(self, *args):
        how = None

        if not isinstance(args, collections.Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            how   = "Not memoizeable!"
            value = self.func(*args)

        if args in self.cache:
            how   = "Cached"
            value = self.cache[args]

        else:
            how   = "Executed"
            value = self.func(*args)
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

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)

    @staticmethod
    @pwndbg.events.stop
    def __reset():
        for obj in reset_on_stop.caches:
            obj.cache.clear()

class reset_on_exit(memoize):
    caches = []
    kind   = 'exit'

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)
        self.__name__ = func.__name__
        self.__module__ = func.__module__

    @staticmethod
    @pwndbg.events.exit
    def __reset():
        for obj in reset_on_exit.caches:
            obj.clear()

class reset_on_objfile(memoize):
    caches = []
    kind   = 'objfile'

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)
        self.__name__ = func.__name__
        self.__module__ = func.__module__

    @staticmethod
    @pwndbg.events.new_objfile
    def __reset():
        for obj in reset_on_objfile.caches:
            obj.clear()

class reset_on_start(memoize):
    caches = []
    kind   = 'start'

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)
        self.__name__ = func.__name__
        self.__module__ = func.__module__

    @staticmethod
    @pwndbg.events.stop
    @pwndbg.events.start
    def __reset():
        for obj in reset_on_start.caches:
            obj.clear()
