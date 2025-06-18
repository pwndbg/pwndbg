from __future__ import annotations

import functools
from typing import Callable
from typing import Coroutine

import host
from host import Controller


def pwndbg_test(
    test: Callable[..., Coroutine[Any, Any, None]],
) -> Callable[..., None]:
    @functools.wraps(test)
    def inner_test(*args, **kwargs):
        async def _test(controller: Controller) -> None:
            test(controller, *args, **kwargs)

        host.start(_test)
        pass

    return inner_test
