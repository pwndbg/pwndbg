"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""

from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import Tuple

debug = 0


class _CacheUntilEvent:
    def __init__(self):
        self.caches = []

    def connect_event_hooks(self, event_hooks):
        """
        A given cache until event may require multiple debugger events
        to be handled properly. E.g. our `stop` cache needs to be handled
        by `stop`, `mem_changed` and `reg_changed` events.
        """
        for event_hook in event_hooks:
            event_hook(self.clear)

    def clear(self):
        for cache in self.caches:
            cache.clear()

    def add_cache(self, cache):
        self.caches.append(cache)


# This is not used anywhere, but it might be useful in the future.
# To make it work, the `IS_CACHING` needs to be per-cache, not global.
# To implement that, we need to:
# 1. Change the `inner` decorator below to pass `func` to the event
# 2. Set `func.is_caching=True` in `decorator` below
# 3. Use `if func.is_caching` instead of `if IS_CACHING` in `decorator`
# All this would allow the `_CacheWhileRunning` to set the
# `is_caching` status based on start/exit events.
# class _CacheWhileRunning(_CacheUntilEvent):
#    def __init__(self):
#        super().__init__(event_exit)
#        self.func = None
#
#    def connect_event_hooks(self, event_start, event_exit):
#        event_start(self.__start_caching)
#        event_exit(self.clear)
#
#    def add_cache(self, cache, func):
#        super().add_cache(cache)
#        self.func = func
#
#    @pwndbg.gdblib.events.start
#    @staticmethod
#    def __start_caching():
#        self.func.is_caching = True
#
#    def clear(self):
#        super().clear()
#        self.func.is_caching = False


_ALL_CACHE_UNTIL_EVENTS = {
    "stop": _CacheUntilEvent(),
    "exit": _CacheUntilEvent(),
    "objfile": _CacheUntilEvent(),
    "start": _CacheUntilEvent(),
    "cont": _CacheUntilEvent(),
    "thread": _CacheUntilEvent(),
    "prompt": _CacheUntilEvent(),
    "forever": _CacheUntilEvent(),
}


def connect_clear_caching_events(event_tuples):
    """
    Connect given debugger event hooks to correspoonding _CacheUntilEvent instances
    """
    for (event_name, event_hooks) in event_tuples:
        _ALL_CACHE_UNTIL_EVENTS[event_name].connect_event_hooks(event_hooks)


# A singleton used to mark a cache miss
_NOT_FOUND_IN_CACHE = object()
_KWARGS_SEPARATOR = object()

# Global value whether the results from cache are returned or not
IS_CACHING = True


def cache_until(*event_names) -> Callable:
    def inner(func):
        if hasattr(func, "cache"):
            raise ValueError(
                f"Cannot cache the {func.__name__} function twice! "
                "Pass multiple event names to the `cache_until` decorator."
            )

        cache: Dict[Tuple[Any], Any] = {}

        @wraps(func)
        def decorator(*a, **kw):
            if IS_CACHING:
                key: Tuple[Any] = (a, _KWARGS_SEPARATOR, *kw.items())
                value = cache.get(key, _NOT_FOUND_IN_CACHE)
                if value is not _NOT_FOUND_IN_CACHE:
                    return value

                value = func(*a, **kw)

                # Sanity check; should we maybe do it only in debug?
                # TODO/FIXME: Should we do similar sanity check for args/kwargs?
                if isinstance(value, list):
                    print(f"Should not cache mutable types! {func.__name__}")

                cache[key] = value

                return value

            return func(*a, **kw)

        decorator.cache = cache

        # Register the cache for the given event so it can be cleared
        for event_name in event_names:
            _ALL_CACHE_UNTIL_EVENTS[event_name].add_cache(cache)

        return decorator

    return inner


def clear_caches() -> None:
    for cache in _ALL_CACHE_UNTIL_EVENTS.values():
        cache.clear()
