from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

BINARY = get_binary("reference-binary.native.out")
TELESCOPE_BINARY = get_binary("telescope_binary.native.out")


@pwndbg_test
async def test_cache_single_value(ctrl: Controller) -> None:
    from pwndbg.lib import cache

    x = 0

    @cache.cache_until("stop")
    def foo():
        nonlocal x
        x += 1
        # Typically its bad idea to cache a non-local/global variable
        # but we need this for testing purposes :)
        return x

    assert foo() == x == 1

    # The function result should now be pulled from cache
    # so that `x` should not change as well
    assert foo() == x == 1

    cache.clear_function_cache(foo)

    assert foo() == x == 2
    assert foo() == x == 2

    # Check if cache is properly cleared on a stop event
    await ctrl.launch(BINARY)
    assert foo() == x == 3
    assert foo() == x == 3


@pwndbg_test
async def test_cache_args_kwargs_properly(ctrl: Controller) -> None:
    from pwndbg.lib import cache

    x = 0

    @cache.cache_until("stop")
    def foo(arg0, *args, **kwargs):
        nonlocal x
        x += 1

        # Typically its bad idea to cache a non-local/global variable
        # but we need this for testing purposes :)
        return x, arg0, args, kwargs

    assert foo("abc") == (1, "abc", (), {}) and x == 1
    assert foo("abc") == (1, "abc", (), {}) and x == 1

    assert foo(100, 200) == (2, 100, (200,), {}) and x == 2
    assert foo(100, 200) == (2, 100, (200,), {}) and x == 2

    assert foo("abc") == (1, "abc", (), {}) and x == 2
    assert foo(100, 200) == (2, 100, (200,), {}) and x == 2

    cache.clear_function_cache(foo)

    assert foo("abc") == (3, "abc", (), {}) and x == 3
    assert foo("abc") == (3, "abc", (), {}) and x == 3

    assert foo(100, 200) == (4, 100, (200,), {}) and x == 4
    assert foo(100, 200) == (4, 100, (200,), {}) and x == 4

    # Check if cache is properly cleared on a stop event
    await ctrl.launch(BINARY)

    assert foo("abc") == (5, "abc", (), {}) and x == 5
    assert foo(100, 200) == (6, 100, (200,), {}) and x == 6


@pwndbg_test
async def test_cache_clear_has_priority(ctrl: Controller) -> None:
    import pwndbg
    from pwndbg.dbg_mod import EventType
    from pwndbg.lib import cache

    actions = []

    @pwndbg.dbg.event_handler(EventType.STOP)
    def on_stop():
        actions.append("on_stop")
        # test to make sure event handlers don't have a stale cache
        foo()

    @cache.cache_until("stop")
    def foo():
        actions.append("foo")

    foo()
    foo()
    assert actions == ["foo"]

    await ctrl.launch(BINARY)
    assert actions == ["foo", "on_stop", "foo"]

    foo()
    foo()
    assert actions == ["foo", "on_stop", "foo"]


@pwndbg_test
async def test_cache_registers_account_frame(ctrl: Controller) -> None:
    # Test that the registers don't get cached without an associated frame
    # and thus reuse a stale value.
    # https://github.com/pwndbg/pwndbg/issues/3508
    import pwndbg.aglib

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    # Get the value of pc in the freshest stack frame
    pc1 = pwndbg.aglib.regs.pc

    # Get the value of pc in a higher stack frame
    await ctrl.execute("up")
    pc2 = pwndbg.aglib.regs.pc

    assert pc1 != pc2
