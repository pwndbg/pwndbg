from __future__ import annotations

import gdb

import pwndbg.aglib.regs
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_with_required_args_shouldnt_exit_debugger(start_binary):
    start_binary(REFERENCE_BINARY)

    result = gdb.execute("distance", to_string=True)
    assert "the following arguments are required" in result

    result = gdb.execute("distance", to_string=True)
    assert "the following arguments are required" in result
