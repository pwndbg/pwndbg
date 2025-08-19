from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

TLS_X86_64_BINARY = get_binary("tls.x86-64.out")
TLS_I386_BINARY = get_binary("tls.i386.out")


# TODO: Support other architectures
@pwndbg_test
@pytest.mark.parametrize("binary", [TLS_X86_64_BINARY, TLS_I386_BINARY], ids=["x86-64", "i386"])
async def test_tls_address_and_command(ctrl: Controller, binary: str):
    import pwndbg.aglib.tls
    import pwndbg.aglib.vmmap
    from pwndbg.dbg import DebuggerType

    if pwndbg.dbg.name() == DebuggerType.LLDB and binary == TLS_I386_BINARY:
        pytest.skip("TLS commands are flaky in LLDB on i386")
        return

    await launch_to(ctrl, binary, "break_here")

    expected_tls_address = int(
        pwndbg.dbg.selected_frame().evaluate_expression("(void *)tls_address")
    )

    assert pwndbg.aglib.tls.find_address_with_register() == expected_tls_address

    assert pwndbg.aglib.tls.find_address_with_pthread_self() == expected_tls_address

    output = await ctrl.execute_and_capture("tls")

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output
    assert "TLS is located at:\n" and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output
    assert "Output truncated. Rerun with option -a to display the full output." in output

    output_pthread = await ctrl.execute_and_capture("tls --pthread-self")

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output_pthread
    assert (
        "TLS is located at:"
        and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output_pthread
    )
    assert "Output truncated. Rerun with option -a to display the full output." in output_pthread

    # Argument `-a`
    output_all = await ctrl.execute_and_capture("tls --all")

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output_all
    assert (
        "TLS is located at:\n"
        and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output_all
    )
    assert "Output truncated. Rerun with option -a to display the full output." not in output_all
