from __future__ import annotations

import gdb
import pytest

import pwndbg.aglib.tls
import pwndbg.aglib.vmmap
import tests

TLS_X86_64_BINARY = tests.binaries.get("tls.x86-64.out")
TLS_I386_BINARY = tests.binaries.get("tls.i386.out")


# TODO: Support other architectures
@pytest.mark.parametrize("binary", [TLS_X86_64_BINARY, TLS_I386_BINARY], ids=["x86-64", "i386"])
def test_tls_address_and_command(start_binary, binary):
    try:
        start_binary(binary)
    except gdb.error:
        pytest.skip("This device does not support this test")
    gdb.execute("break break_here")
    gdb.execute("continue")

    expected_tls_address = int(gdb.parse_and_eval("(void *)tls_address"))

    assert pwndbg.aglib.tls.find_address_with_register() == expected_tls_address

    assert pwndbg.aglib.tls.find_address_with_pthread_self() == expected_tls_address

    output = gdb.execute("tls", to_string=True)

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output
    assert "TLS is located at:\n" and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output
    assert "Output truncated. Rerun with option -a to display the full output." in output

    output_pthread = gdb.execute("tls --pthread-self", to_string=True)

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output_pthread
    assert (
        "TLS is located at:"
        and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output_pthread
    )
    assert "Output truncated. Rerun with option -a to display the full output." in output_pthread

    # Argument `-a`
    output_all = gdb.execute("tls --all", to_string=True)

    assert f"Thread Local Storage (TLS) base: {expected_tls_address:#x}" in output_all
    assert (
        "TLS is located at:\n"
        and f"{pwndbg.aglib.vmmap.find(expected_tls_address)}\n" in output_all
    )
    assert "Output truncated. Rerun with option -a to display the full output." not in output_all
