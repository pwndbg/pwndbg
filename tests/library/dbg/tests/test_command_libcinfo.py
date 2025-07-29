from __future__ import annotations

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")


@pwndbg_test
async def test_command_libcinfo(ctrl: Controller) -> None:
    """
    Tests the libcinfo command
    """
    await ctrl.launch(REFERENCE_BINARY)

    result = await ctrl.execute_and_capture("libcinfo")
    assert result == "Could not determine libc version.\n"

    # Continue until main, so the libc is actually loaded
    break_at_sym("main")
    await ctrl.cont()

    result = (await ctrl.execute_and_capture("libcinfo")).splitlines()
    assert len(result) == 2
    assert result[0].startswith("libc version: ")
    assert result[1].startswith("libc source link: https://ftp.gnu.org/gnu/libc/glibc-")
    assert result[1].endswith(".tar.gz")
