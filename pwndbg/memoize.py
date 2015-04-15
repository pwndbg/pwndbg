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


class memoize(object):
    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            return self.func(*args)

        if args in self.cache:
            return self.cache[args]

        value = self.func(*args)
        self.cache[args] = value

        if isinstance(value, list):
            print("Shouldnt cache mutable types! %r" % self.func.__name__)

        return value

    def __repr__(self):
        return self.func.__doc__

    def __get__(self, obj, objtype):
        return functools.partial(self.__call__, obj)

    def clear(self):
        self.cache.clear()



class reset_on_stop(memoize):
    caches = []

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
