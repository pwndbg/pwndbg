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
from typing import List  # noqa: F401

debug = 0

# function -> function wrapper
wrappers = {}
functions_to_reset_on = {}

_kwargs_separator = object()
_sentinel = object()

def _reset_on(func, kind, reset_list):
    if func in reset_list:
        raise ValueError("Function's %s cache is already registered to be resetted on %s" % (func.__name__, kind))
    reset_list.append(func)

    wrapper_func = wrappers.get(func)
    if wrapper_func is not None:
        #print(f"[{func.__name__}] ({kind}) already registered for caching")
        return wrapper_func
    #print(f"[{func.__name__}] ({kind}) registered for caching")

    # If we encounter this function for the first time we create the
    # cache and wrapper function
    cache = {}

    # save cache and its clear method in function
    func.cache = cache
    func.clear_cache = cache.clear

    @functools.wraps(func)
    def wrapper_func(*args, **kwargs):
        # Based on functools.lru_cache / functools.cache
        # but they have lots of code we don't need
        key = args
        if kwargs:
            key += (_kwargs_separator,)
            # Note that we rely on the dict order here, meaning that
            # func(x=1, y=2) and func(y=2, x=1) will be cached separately
            key += tuple(kwargs.items())

        result = cache.get(key, _sentinel)
        if result is not _sentinel:
            if debug: print(f"[{func.__name__}] cache hit: {key}")
            return result

        if debug: print(f"[{func.__name__}] cache miss: {key}")
        result = func(*args, **kwargs)
        cache[key] = result
        #print(cache)

        return result

    # Save the wrapper
    wrappers[func] = wrapper_func
    return wrapper_func


def create_caching_function(kind):
    reset_list = []
    functions_to_reset_on[kind] = reset_list
    func = functools.partial(_reset_on, kind=kind, reset_list=reset_list)

    def reset_cache():
        for f in reset_list:
            f.clear_cache()

    func._reset = reset_cache
    return func

forever = create_caching_function("forever")
reset_on_stop = create_caching_function("stop")
reset_on_exit = create_caching_function("exit")
reset_on_objfile = create_caching_function("objfile")
reset_on_start = create_caching_function("start")
reset_on_cont = create_caching_function("cont")
reset_on_prompt = create_caching_function("prompt")
reset_on_thread = create_caching_function("thread")
while_running = create_caching_function("running")


def reset() -> None:
    forever._reset()
    reset_on_stop._reset()
    reset_on_exit._reset()
    reset_on_objfile._reset()
    reset_on_start._reset()
    reset_on_cont._reset()
    while_running._reset()
