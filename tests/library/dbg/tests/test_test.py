"""
Metatests.

These tests are intended to check the functioning of the testing code itself,
rather than of Pwndbg more generally.

Some tests come in SUCCESS and XFAIL pairs, and they require that both succeed
in order for the overall test to succeed, as they contain no inner test logic
other than the minimum necessary to start the asynchronous controller function.

This module is responsible for testing the pwndbg_test decorator for async
controller tests.
"""

from __future__ import annotations

import pytest

from .... import host
from ....host import Controller
from . import get_binary
from . import pwndbg_test


@pytest.mark.xfail
def test_starts_no_decorator_xfail() -> None:
    async def run(ctrl: Controller):
        raise RuntimeError("should fail!")

    host.start(run)


def test_starts_no_decorator() -> None:
    async def run(ctrl: Controller):
        pass

    host.start(run)


@pytest.mark.xfail
@pwndbg_test
async def test_starts_xfail(ctrl: Controller) -> None:
    raise RuntimeError("should fail")


@pwndbg_test
async def test_starts(ctrl: Controller) -> None:
    pass


@pwndbg_test
async def test_launch(ctrl: Controller) -> None:
    """
    Launches a process and checks if a simple static CString can be read from it.
    """
    import pwndbg
    import pwndbg.aglib.typeinfo

    await ctrl.launch(get_binary("memory.out"))

    inf = pwndbg.dbg.selected_inferior()
    addr = inf.lookup_symbol("short_str")
    string = addr.cast(pwndbg.aglib.typeinfo.char.pointer()).string()

    assert string == "some cstring here"
