from __future__ import annotations

import functools
import os
from inspect import signature
from typing import Any
from typing import Callable
from typing import Concatenate
from typing import Coroutine
from typing import ParamSpec

from .... import host
from ....host import Controller

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT")

T = ParamSpec("T")


def pwndbg_test(
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


def break_at_sym(sym: str) -> None:
    import pwndbg
    from pwndbg.dbg import BreakpointLocation

    inf = pwndbg.dbg.selected_inferior()
    addr = inf.lookup_symbol(sym)
    inf.break_at(BreakpointLocation(int(addr)))


async def launch_to(ctrl: Controller, target: str, sym: str) -> None:
    import pwndbg
    import pwndbg.aglib.regs
    from pwndbg.dbg import BreakpointLocation

    await ctrl.launch(target)

    inf = pwndbg.dbg.selected_inferior()
    addr = inf.lookup_symbol(sym)
    if pwndbg.aglib.regs.pc != int(addr):
        inf.break_at(BreakpointLocation(int(addr)))
        await ctrl.cont()


def get_expr(expr: str):
    import pwndbg

    ctx = pwndbg.dbg.selected_frame() or pwndbg.dbg.selected_inferior()
    return ctx.evaluate_expression(expr)
