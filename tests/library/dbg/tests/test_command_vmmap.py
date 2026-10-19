from __future__ import annotations

import re

from ....host import Controller
from . import get_binary
from . import pwndbg_test

SMALL_BINARY = get_binary("crash_simple.native.out")


def _starts(output: str) -> list[int]:
    return [
        int(m.group(1), 16)
        for m in re.finditer(r"^\W*(0x[0-9a-f]+)\s+0x[0-9a-f]+\s", output, re.MULTILINE)
    ]


@pwndbg_test
async def test_vmmap_lines_after_includes_last_mapping(ctrl: Controller) -> None:
    await ctrl.launch(SMALL_BINARY)

    starts = _starts(await ctrl.execute_and_capture("vmmap"))
    assert len(starts) >= 2

    out = await ctrl.execute_and_capture(f"vmmap -A 1 -B 0 {starts[-2]:#x}")
    assert _starts(out) == starts[-2:]


@pwndbg_test
async def test_vmmap_address_zero_is_a_filter(ctrl: Controller) -> None:
    await ctrl.launch(SMALL_BINARY)

    out = await ctrl.execute_and_capture("vmmap 0")
    assert "There are no mappings for specified address or module." in out
