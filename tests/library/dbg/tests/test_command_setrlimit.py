from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_setrlimit_unknown_resource(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])

    result = await ctrl.execute_and_capture("setrlimit unknown 1")

    assert "argument resource: invalid choice" in result


@pwndbg_test
async def test_setrlimit_invalid_soft_value(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])
    out = await ctrl.execute_and_capture("setrlimit cpu not-a-number")
    assert "Invalid limit 'not-a-number'" in out


@pwndbg_test
async def test_setrlimit_invalid_hard_value(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])
    out = await ctrl.execute_and_capture("setrlimit cpu 1 invalid_hard")
    assert "Invalid limit 'invalid_hard'" in out


@pwndbg_test
async def test_setrlimit_soft_only_defaults_hard(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY, args=[])
    out = await ctrl.execute_and_capture("setrlimit cpu 10")
    assert "soft=10, hard=10" in out
