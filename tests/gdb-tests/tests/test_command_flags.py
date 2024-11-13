from __future__ import annotations

import gdb

import pwndbg.aglib.regs
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_flags_command(start_binary):
    start_binary(REFERENCE_BINARY)

    old_eflags = pwndbg.aglib.regs.eflags

    # Verify CF is not set
    assert old_eflags & 0x1 == 0

    gdb.execute("setflag cf 1")

    # Verify CF is set and no other flags have changed
    assert (old_eflags | 1) == pwndbg.aglib.regs.eflags

    gdb.execute("setflag cf 0")

    # Verify CF is not set and no other flags have changed
    assert old_eflags == pwndbg.aglib.regs.eflags

    # Test setting an invalid value
    gdb.execute("setflag cf 2")

    # Verify no flags have changed
    assert old_eflags == pwndbg.aglib.regs.eflags
