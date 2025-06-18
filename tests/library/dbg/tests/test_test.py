from __future__ import annotations

import host
import pytest
from host import Controller


@pytest.mark.xfail
def test_starts_no_decorator() -> None:
    async def run(ctrl: Controller):
        raise RuntimeError("should fail!")

    host.start(run)
