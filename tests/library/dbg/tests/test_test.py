from __future__ import annotations

import host
import pytest
from host import Controller

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
