"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""

from __future__ import annotations

from collections import UserDict
from functools import wraps
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple
from typing import TypeVar
from typing import Union

from typing_extensions import ParamSpec

T = TypeVar("T")
P = ParamSpec("P")

# Set to enable print logging of cache hits/misses/clears
NO_DEBUG, DEBUG_GET, DEBUG_CLEAR, DEBUG_SET = 0, 1, 2, 4
# combine the flags with | operator
debug = NO_DEBUG
# debug_name can be used to filter cache results by a given name
debug_name = "regs"


class DebugCacheDict(UserDict):  # type: ignore[type-arg]
    def __init__(self, func: Callable[P, T], *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.hits = 0
        self.misses = 0
        self.func = func
        self.name = f'{func.__module__.split(".")[-1]}.{func.__name__}'

    def __getitem__(self, key: Tuple[Any, ...]) -> Any:
        if debug & DEBUG_GET and (not debug_name or debug_name in self.name):
            print(f"GET {self.name}: {key}")
        try:
            value = self.data[key]
            self.hits += 1
            return value
        except KeyError:
            self.misses += 1
            raise

    def __setitem__(self, key: Tuple[Any, ...], value: Any) -> None:
        if debug & DEBUG_SET and (not debug_name or debug_name in self.name):
            print(f"SET {self.name}: {key}={value}")
        self.data[key] = value

    def clear(self) -> None:
        if debug & DEBUG_CLEAR and (not debug_name or debug_name in self.name):
            print(f"CLEAR {self.name} (hits: {self.hits}, misses: {self.misses})")
        self.data.clear()
        self.hits = 0
        self.misses = 0


Cache = Union[Dict[Tuple[Any, ...], Any], DebugCacheDict]


class _CacheUntilEvent:
    def __init__(self) -> None:
        self.caches: List[Cache] = []

    def connect_event_hooks(self, event_hooks: Tuple[Any, ...], **kwargs: Any) -> None:
        """
        A given _CacheUntilEvent object may require multiple debugger events
        to be handled properly. E.g. our `stop` cache needs to be handled
        by `stop`, `mem_changed` and `reg_changed` events.
        """
        for event_hook in event_hooks:
            event_hook(self.clear, **kwargs)

    def clear(self) -> None:
        for cache in self.caches:
            cache.clear()

    def add_cache(self, cache: Cache) -> None:
        self.caches.append(cache)


_ALL_CACHE_UNTIL_EVENTS: Dict[str, _CacheUntilEvent] = {
    "stop": _CacheUntilEvent(),
    "exit": _CacheUntilEvent(),
    "objfile": _CacheUntilEvent(),
    "start": _CacheUntilEvent(),
    "cont": _CacheUntilEvent(),
    "thread": _CacheUntilEvent(),
    "prompt": _CacheUntilEvent(),
    "forever": _CacheUntilEvent(),
}
_ALL_CACHE_EVENT_NAMES = tuple(_ALL_CACHE_UNTIL_EVENTS.keys())


def connect_clear_caching_events(event_dicts: Dict[str, Tuple[Any, ...]], **kwargs: Any) -> None:
    """
    Connect given debugger event hooks to correspoonding _CacheUntilEvent instances
    """
    for event_name, event_hooks in event_dicts.items():
        _ALL_CACHE_UNTIL_EVENTS[event_name].connect_event_hooks(event_hooks, **kwargs)


# A singleton used to mark a cache miss
_NOT_FOUND_IN_CACHE = object()
_KWARGS_SEPARATOR = object()

# Global value whether the results from cache are returned or not
IS_CACHING = True


# Global value that allows disabling of individual cache types.
IS_CACHING_DISABLED_FOR: Dict[str, bool] = {
    "stop": False,
    "exit": False,
    "objfile": False,
    "start": False,
    "cont": False,
    "thread": False,
    "prompt": False,
    "forever": False,
}


def cache_until(*event_names: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    if any(event_name not in _ALL_CACHE_EVENT_NAMES for event_name in event_names):
        raise ValueError(
            f"Unknown event name[s] passed to the `cache_until` decorator: {event_names}.\n"
            f"Expected: {_ALL_CACHE_EVENT_NAMES}"
        )

    def inner(func: Callable[P, T]) -> Callable[P, T]:
        if hasattr(func, "cache"):
            raise ValueError(
                f"Cannot cache the {func.__name__} function twice! "
                "Pass multiple event names to the `cache_until` decorator."
            )

        cache: Cache = {} if not debug else DebugCacheDict(func)

        @wraps(func)
        def decorator(*a: P.args, **kw: P.kwargs) -> T:
            if IS_CACHING and not any((IS_CACHING_DISABLED_FOR[e] for e in event_names)):
                key: Tuple[Any, ...] = (a, _KWARGS_SEPARATOR, *kw.items())

                # Check if the value is in the cache; if we have a cache miss,
                # we return a special singleton object `_NOT_FOUND_IN_CACHE`. This way
                # we can also cache a result of 'None' from a function
                try:
                    cached_value: Any = cache.get(key, _NOT_FOUND_IN_CACHE)
                except TypeError:
                    # skip caching unhashable arguments
                    return func(*a, **kw)
                if cached_value is not _NOT_FOUND_IN_CACHE:
                    return cached_value

                value = func(*a, **kw)

                # Sanity check: its not perfect and won't cover all cases like ([],)
                # but it should be good enough
                if isinstance(value, list):
                    print(f"Should not cache mutable types! {func.__name__}")

                cache[key] = value

                return value

            return func(*a, **kw)

        # Set the cache on the function so it can be cleared on demand
        # this may be useful for tests
        decorator.cache = cache  # type: ignore[attr-defined]

        # Register the cache for the given event so it can be cleared
        for event_name in event_names:
            _ALL_CACHE_UNTIL_EVENTS[event_name].add_cache(cache)

        return decorator

    return inner


def clear_caches() -> None:
    for cache in _ALL_CACHE_UNTIL_EVENTS.values():
        cache.clear()


def clear_cache(cache_name: str) -> None:
    _ALL_CACHE_UNTIL_EVENTS[cache_name].clear()
