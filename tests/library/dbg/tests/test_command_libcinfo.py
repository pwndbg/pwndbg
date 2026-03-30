from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_libcinfo(ctrl: Controller) -> None:
    """
    Tests the libcinfo command
    """
    await ctrl.launch(REFERENCE_BINARY)

    result = await ctrl.execute_and_capture("libcinfo")
    assert result.splitlines()[0] == "libc: unknown"

    # Continue until main, so the libc is actually loaded
    break_at_sym("main")
    await ctrl.cont()

    result = (await ctrl.execute_and_capture("libcinfo")).splitlines()
    assert len(result) == 17
    assert result[0] == "libc: glibc"
    assert "libc version: 2." in result[1] and result[1] != "libc version: no version information"
    assert result[2] == "linked: dynamically"
    assert result[-1] == "    has debug info:        yes"
    assert result[-2] == "    has internal symbols:  yes"
    assert result[-3] == "    has exported symbols:  yes"
    assert "libc.so.6" in result[10]
    assert "ld-linux" in result[12]
