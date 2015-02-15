import collections
import gdb
import functools
import sys

class memoize(object):
    caches = []

    def __init__(self, func):
        self.func  = func
        self.cache = {}
        self.caches.append(self)

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

    @staticmethod
    def reset():
        print("Evicting cache")
        for obj in memoize.caches:
            if obj.cache:
                print(obj.func)
                obj.cache.clear()

def reset(*a):
    memoize.reset()

gdb.events.cont.connect(reset)
gdb.events.exited.connect(reset)
gdb.events.stop.connect(reset)
gdb.events.new_objfile.connect(reset)
