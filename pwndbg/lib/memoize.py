"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""

import functools
import sys
from collections.abc import Hashable
from typing import Any
from typing import Callable
from typing import Dict
from typing import List

debug = False


class memoize:
    """
    Base memoization class. Do not use directly. Instead use one of classes defined below.
    """

    caching = True

    def __init__(self, func: Callable) -> None:
        self.func = func
        self.cache = {}  # type: Dict[Any,Any]
        self.caches.append(self)  # must be provided by base class
        functools.update_wrapper(self, func)

    def __call__(self, *args: Any, **kwargs: Any) -> int:
        how = None

        if not isinstance(args, Hashable):
            print("Cannot memoize %r!", file=sys.stderr)
            how = "Not memoizeable!"
            value = self.func(*args)

        if self.caching and args in self.cache:
            how = "Cached"
            value = self.cache[args]

        else:
            how = "Executed"
            value = self.func(*args, **kwargs)
            self.cache[args] = value

            if isinstance(value, list):
                print("Should not cache mutable types! %r" % self.func.__name__)

        if debug:
            print("%s: %s(%r)" % (how, self, args))
            print(".... %r" % (value,))
        return value

    def __repr__(self):
        funcname = self.func.__module__ + "." + self.func.__name__
        return "<%s-memoized function %s>" % (self.kind, funcname)

    def __get__(self, obj, objtype: type) -> Callable:
        return functools.partial(self.__call__, obj)

    def clear(self) -> None:
        if debug:
            print("Clearing %s %r" % (self, self.cache))
        self.cache.clear()


class forever(memoize):
    """
    Memoizes forever - for a pwndbg session or until `_reset` is called explicitly.
    """

    caches = []  # type: List[forever]

    @staticmethod
    def _reset():
        for obj in forever.caches:
            obj.cache.clear()


class reset_on_stop(memoize):
    caches = []  # type: List[reset_on_stop]
    kind = "stop"

    @staticmethod
    def __reset_on_stop() -> None:
        for obj in reset_on_stop.caches:
            obj.cache.clear()

    _reset = __reset_on_stop


class reset_on_prompt(memoize):
    caches = []  # type: List[reset_on_prompt]
    kind = "prompt"

    @staticmethod
    def __reset_on_prompt():
        for obj in reset_on_prompt.caches:
            obj.cache.clear()

    _reset = __reset_on_prompt


class reset_on_exit(memoize):
    caches = []  # type: List[reset_on_exit]
    kind = "exit"

    @staticmethod
    def __reset_on_exit() -> None:
        for obj in reset_on_exit.caches:
            obj.clear()

    _reset = __reset_on_exit


class reset_on_objfile(memoize):
    caches = []  # type: List[reset_on_objfile]
    kind = "objfile"

    @staticmethod
    def __reset_on_objfile() -> None:
        for obj in reset_on_objfile.caches:
            obj.clear()

    _reset = __reset_on_objfile


class reset_on_start(memoize):
    caches = []  # type: List[reset_on_start]
    kind = "start"

    @staticmethod
    def __reset_on_start() -> None:
        for obj in reset_on_start.caches:
            obj.clear()

    _reset = __reset_on_start


class reset_on_cont(memoize):
    caches = []  # type: List[reset_on_cont]
    kind = "cont"

    @staticmethod
    def __reset_on_cont() -> None:
        for obj in reset_on_cont.caches:
            obj.clear()

    _reset = __reset_on_cont


class reset_on_thread(memoize):
    caches = []  # type: List[reset_on_thread]
    kind = "thread"

    @staticmethod
    def __reset_on_thread() -> None:
        for obj in reset_on_thread.caches:
            obj.clear()

    _reset = __reset_on_thread


class while_running(memoize):
    caches = []  # type: List[while_running]
    kind = "running"
    caching = False

    @staticmethod
    def _start_caching() -> None:
        while_running.caching = True

    @staticmethod
    def __reset_while_running() -> None:
        for obj in while_running.caches:
            obj.clear()
        while_running.caching = False

    _reset = __reset_while_running


def reset():
    forever._reset()
    reset_on_stop._reset()
    reset_on_exit._reset()
    reset_on_objfile._reset()
    reset_on_start._reset()
    reset_on_cont._reset()
    while_running._reset()
