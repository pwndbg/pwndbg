from __future__ import annotations

import functools
import os
from inspect import signature
from typing import Any
from typing import Callable
from typing import Concatenate
from typing import Coroutine

from .... import host
from ....host import Controller

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT")


def pwndbg_test[**T](
    test: Callable[Concatenate[Controller, T], Coroutine[Any, Any, None]],
) -> Callable[T, None]:
    @functools.wraps(test)
    def inner_test(*args: T.args, **kwargs: T.kwargs) -> None:
        async def _test(controller: Controller) -> None:
            await test(controller, *args, **kwargs)

        print(f"[+] Launching test {test.__name__} asynchronously")
        host.start(_test)

    # Remove the controller from the signature, as seen by Pytest.
    sig = signature(inner_test)
    sig = sig.replace(parameters=tuple(sig.parameters.values())[1:])
    inner_test.__signature__ = sig

    return inner_test


def get_binary(name: str) -> str:
    return os.path.join(BINARIES_PATH, name)
