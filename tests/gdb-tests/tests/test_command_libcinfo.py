from __future__ import annotations

import gdb

import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_libcinfo(start_binary):
    """
    Tests the libcinfo command
    """
    start_binary(REFERENCE_BINARY)

    result = gdb.execute("libcinfo", to_string=True)
    assert result == "Could not determine libc version.\n"

    # Continue until main, so the libc is actually loaded
    gdb.execute("break main")
    gdb.execute("continue")

    result = gdb.execute("libcinfo", to_string=True).splitlines()
    assert len(result) == 2
    assert result[0].startswith("libc version: ")
    assert result[1].startswith("libc source link: https://ftp.gnu.org/gnu/libc/glibc-")
    assert result[1].endswith(".tar.gz")
