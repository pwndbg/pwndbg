from __future__ import annotations

from host import Controller

from tests import pwndbg_test


@pwndbg_test
async def test_empty(ctrl: Controller) -> None:
    pass
