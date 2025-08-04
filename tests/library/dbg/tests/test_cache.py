from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

BINARY = get_binary("reference-binary.out")


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

    foo.cache.clear()

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

    foo.cache.clear()

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
    from pwndbg.dbg import EventType
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
