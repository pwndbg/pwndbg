"""
Caches return values until some event in the inferior happens,
e.g. execution stops because of a SIGINT or breakpoint, or a
new library/objfile are loaded, etc.
"""

from __future__ import annotations

from collections import UserDict
from collections.abc import Callable
from enum import IntFlag
from functools import wraps
from typing import Any
from typing import TypeAlias
from typing import TypeVar

from typing_extensions import ParamSpec

T = TypeVar("T", covariant=True)
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
        self.name = f"{func.__module__.split('.')[-1]}.{func.__name__}"

    def __getitem__(self, key: tuple[Any, ...]) -> Any:
        if debug & DEBUG_GET and (not debug_name or debug_name in self.name):
            print(f"GET {self.name}: {key}")
        try:
            value = self.data[key]
            self.hits += 1
            return value
        except KeyError:
            self.misses += 1
            raise

    def __setitem__(self, key: tuple[Any, ...], value: Any) -> None:
        if debug & DEBUG_SET and (not debug_name or debug_name in self.name):
            print(f"SET {self.name}: {key}={value}")
        self.data[key] = value

    def clear(self) -> None:
        if debug & DEBUG_CLEAR and (not debug_name or debug_name in self.name):
            print(f"CLEAR {self.name} (hits: {self.hits}, misses: {self.misses})")
        self.data.clear()
        self.hits = 0
        self.misses = 0


Cache: TypeAlias = dict[tuple[Any, ...], Any] | DebugCacheDict


class _CacheUntilEvent:
    def __init__(self) -> None:
        self.caches: list[Cache] = []

    def connect_event_hooks(self, event_hooks: tuple[Any, ...]) -> None:
        """
        A given _CacheUntilEvent object may require multiple debugger events
        to be handled properly. E.g. our `stop` cache needs to be handled
        by `stop`, `mem_changed` and `reg_changed` events.
        """
        for event_hook in event_hooks:
            # This will just run a decorator (which will return a function, but
            # that return value is not used here).
            event_hook(self.clear)

    def clear(self) -> None:
        for cache in self.caches:
            cache.clear()

    def add_cache(self, cache: Cache) -> None:
        self.caches.append(cache)


# fmt: off
class CacheUntilEvent(IntFlag):
    """
    Not necessarily 1:1 with pwndbg.dbg_mod.EventTypes , but
    read the definition of that enum to get an idea of how these
    work.

    Notably, STOP is also triggered when the user changes debugee
    memory or register state.
    """
    STOP    = 0b00000001
    EXIT    = 0b00000010
    OBJFILE = 0b00000100
    START   = 0b00001000
    CONT    = 0b00010000
    THREAD  = 0b00100000
    FOREVER = 0b01000000

# fmt: on

# OR (|) events together to make a set
EventSet: TypeAlias = int


_ALL_CACHE_UNTIL_EVENTS: dict[CacheUntilEvent, _CacheUntilEvent] = {
    CacheUntilEvent.STOP: _CacheUntilEvent(),
    CacheUntilEvent.EXIT: _CacheUntilEvent(),
    CacheUntilEvent.OBJFILE: _CacheUntilEvent(),
    CacheUntilEvent.START: _CacheUntilEvent(),
    CacheUntilEvent.CONT: _CacheUntilEvent(),
    CacheUntilEvent.THREAD: _CacheUntilEvent(),
    CacheUntilEvent.FOREVER: _CacheUntilEvent(),
}

_NAME_TO_EVENT: dict[str, CacheUntilEvent] = {
    "stop": CacheUntilEvent.STOP,
    "exit": CacheUntilEvent.EXIT,
    "objfile": CacheUntilEvent.OBJFILE,
    "start": CacheUntilEvent.START,
    "cont": CacheUntilEvent.CONT,
    "thread": CacheUntilEvent.THREAD,
    "forever": CacheUntilEvent.FOREVER,
}
_ALL_CACHE_EVENT_NAMES = tuple(_NAME_TO_EVENT.keys())


def events_to_event_set(event_list: list[CacheUntilEvent]) -> EventSet:
    res = 0
    for an_event in event_list:
        res |= an_event.value
    return res


def connect_clear_caching_events(event_dicts: dict[CacheUntilEvent, tuple[Any, ...]]) -> None:
    """
    Connect given debugger event hooks to corresponding _CacheUntilEvent instances
    """
    for event_name, event_hooks in event_dicts.items():
        _ALL_CACHE_UNTIL_EVENTS[event_name].connect_event_hooks(event_hooks)


# A singleton used to mark a cache miss
_NOT_FOUND_IN_CACHE = object()
_KWARGS_SEPARATOR = object()

# Global value whether the results from cache are returned or not
# Used for debugging (by pwndbg.commands.memoize).
IS_CACHING = True


# Global value that allows disabling of individual cache types.
# This should only be set by the debugger at bring-up time. Thus
# it should be possible to perform this check at decoration time
# rather than at runtime and get a nice performance improvement, but
# I'm not sure how to do this safely exactly.
# The value is an event set (an OR (|) of different events)
IS_CACHING_DISABLED_FOR: EventSet = 0


def cache_until(*event_names: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    All possible values of the function arguments must be hashable
    (so e.g. `var: MyUnhashableType | None = None` is not allowed, but may fail rarely).
    The return value of the function should not be mutable, must not be mutated.
    """
    if any(event_name not in _ALL_CACHE_EVENT_NAMES for event_name in event_names):
        raise ValueError(
            f"Unknown event name[s] passed to the `cache_until` decorator: {event_names}.\n"
            f"Expected: {_ALL_CACHE_EVENT_NAMES}"
        )

    # We could require that CacheUntilEvent's be passed instead of strings as cache_until arguments.
    event_list: list[CacheUntilEvent] = [_NAME_TO_EVENT[event_name] for event_name in event_names]
    event_set: EventSet = events_to_event_set(event_list)

    def inner(func: Callable[P, T]) -> Callable[P, T]:
        if hasattr(func, "cache"):
            raise ValueError(
                f"Cannot cache the {func.__name__} function twice! "
                "Pass multiple event names to the `cache_until` decorator."
            )

        cache: Cache = {} if not debug else DebugCacheDict(func)

        @wraps(func)
        def decorator(*a: P.args, **kw: P.kwargs) -> T:
            if IS_CACHING and (event_set & IS_CACHING_DISABLED_FOR) == 0:
                key: tuple[Any, ...] = (a, _KWARGS_SEPARATOR, *kw.items())

                # Check if the value is in the cache; if we have a cache miss,
                # we return a special singleton object `_NOT_FOUND_IN_CACHE`. This way
                # we can also cache a result of 'None' from a function
                try:
                    cached_value: Any = cache.get(key, _NOT_FOUND_IN_CACHE)
                except TypeError:
                    print("Unhashable argument passed to a cache_until decorated function.")
                    print("Make the argument hashable or refactor.")
                    print(
                        f"Function: {func.__module__}.{func.__qualname__}",
                    )
                    print(f"Arguments: {repr(key)}")
                    assert False, "Unhashable argument passed to a cache_until decorated function."

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
        for an_event in event_list:
            _ALL_CACHE_UNTIL_EVENTS[an_event].add_cache(cache)

        return decorator

    return inner


def clear_caches() -> None:
    for cache in _ALL_CACHE_UNTIL_EVENTS.values():
        cache.clear()


def clear_cache(cache_event: CacheUntilEvent) -> None:
    # I could imagine this being a hot path, so I don't want to do the
    # `str -> CacheUntilEvent` conversion here.
    _ALL_CACHE_UNTIL_EVENTS[cache_event].clear()


def clear_function_cache(func: Callable[..., T]) -> None:
    """
    Call this on a cached function/method to clear its cache. For methods,
    clears the cache for all object instances.
    """
    assert hasattr(func, "cache")
    getattr(func, "cache").clear()
