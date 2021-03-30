#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""

import collections
import functools
import sys

import gdb

import pwndbg.events

debug = False


class memoize:
    """
    Base memoization class. Do not use directly. Instead use one of classes defined below.
    """
    caching = True

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)  # must be provided by base class
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


class forever(memoize):
    """
    Memoizes forever - for a pwndbg session or until `_reset` is called explicitly.
    """
    caches = []

    @staticmethod
    def _reset():
        for obj in forever.caches:
            obj.cache.clear()


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


class reset_on_prompt(memoize):
    caches = []
    kind   = 'prompt'

    @staticmethod
    @pwndbg.events.before_prompt
    def __reset_on_prompt():
        for obj in reset_on_prompt.caches:
            obj.cache.clear()

    _reset = __reset_on_prompt


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


class reset_on_new_base_address(memoize):
    caches   = []
    kind     = 'new_base_address'
    filename = None
    base     = None

    @staticmethod
    @pwndbg.events.start
    @pwndbg.events.new_objfile
    def __reset_on_base():
        filename = gdb.current_progspace().filename
        base = pwndbg.elf.exe().address if pwndbg.elf.exe() else None
        if reset_on_new_base_address.base != base or reset_on_new_base_address.filename != filename:
            reset_on_new_base_address.filename = filename
            reset_on_new_base_address.base = base
            for obj in reset_on_new_base_address.caches:
                obj.clear()

    _reset = __reset_on_base


def reset():
    forever._reset()
    reset_on_stop._reset()
    reset_on_exit._reset()
    reset_on_objfile._reset()
    reset_on_start._reset()
    reset_on_cont._reset()
    reset_on_new_base_address._reset()
    while_running._reset()
