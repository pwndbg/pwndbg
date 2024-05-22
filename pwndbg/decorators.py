from __future__ import annotations

import functools
from typing import Callable
from typing import TypeVar

from typing_extensions import ParamSpec

first_prompt = False

P = ParamSpec("P")
T = TypeVar("T")


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
