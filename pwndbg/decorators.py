from __future__ import annotations

import functools
import traceback
from typing import Callable
from typing import TypeVar

from typing_extensions import ParamSpec

import pwndbg
from pwndbg.color import message

first_prompt = False

P = ParamSpec("P")
T = TypeVar("T")
K = TypeVar("K")


def only_after_first_prompt(
    value_before: T | None = None,
) -> Callable[[Callable[P, T]], Callable[P, T | None]]:
    """
    Decorator to prevent a function from running before the first prompt was displayed.
    The 'value_before' parameter can be used to specify the value that is
    returned if the function is called before the first prompt was displayed.
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T | None]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | None:
            if first_prompt:
                return func(*args, **kwargs)
            else:
                return value_before

        return wrapper

    return decorator


def suppress_errors(
    fallback: K = None, should_warn: bool = True
) -> Callable[[Callable[P, T]], Callable[P, T | K]]:
    """
    Decorator to make a function return a fallback value when it would otherwise error.
    The 'fallback' parameter can be used to specify the fallback value.
    If the 'should_warn' parameter is set, a warning will be printed whenever an error is suppressed.
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T | K]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T | K:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if should_warn:
                    print(message.warn(f"Warning: Received an error in {func.__name__}: {e}"))
                    if pwndbg.config.exception_verbose:
                        traceback.print_exc()
                return fallback

        return wrapper

    return decorator
