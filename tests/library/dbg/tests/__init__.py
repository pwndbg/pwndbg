from __future__ import annotations

import functools
from inspect import signature
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
            await test(controller, *args, **kwargs)

        print(f"[+] Launching test {test.__name__} asynchronously")
        host.start(_test)
        pass

    # Remove the controller from the signature, as seen by Pytest.
    sig = signature(inner_test)
    sig = sig.replace(parameters=tuple(sig.parameters.values())[1:])
    inner_test.__signature__ = sig

    return inner_test
