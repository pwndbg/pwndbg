from __future__ import annotations

import gdb

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def test_convenience_vars_unset_until_mapping_exists(start_binary):
    # `starti` stops before the dynamic loader mapped libc.
    start_binary(REFERENCE_BINARY)

    assert gdb.convenience_variable("stack") is not None
    assert gdb.convenience_variable("ld") is not None
    assert gdb.convenience_variable("libc") is None

    gdb.execute("break main")
    gdb.execute("continue")

    assert gdb.convenience_variable("libc") is not None


def test_convenience_vars_are_cleared_when_the_process_exits(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("continue")
    assert gdb.convenience_variable("libc") is not None

    gdb.execute("delete")
    gdb.execute("continue")

    for name in ("stack", "heap", "libc", "ld", "vdso", "vvar"):
        assert gdb.convenience_variable(name) is None, f"${name}"

    # Nothing stale is visible when the program is started again.
    gdb.execute("starti")
    assert gdb.convenience_variable("libc") is None
    assert gdb.convenience_variable("stack") is not None
