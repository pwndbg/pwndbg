import collections
import gdb
import functools
import sys

import gef.events

class memoize(object):
    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            return self.func(*args)

        if args in self.cache:
            return self.cache[args]

        value = self.func(*args)
        self.cache[args] = value
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
    @gef.events.stop
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
    @gef.events.exit
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
    @gef.events.new_objfile
    def __reset():
        for obj in reset_on_objfile.caches:
            obj.clear()

