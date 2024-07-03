from __future__ import annotations

import sys
import traceback

import gdb
import user

import pwndbg

REFERENCE_BINARY = user.binaries.get("reference-binary.riscv64.out")


def test_riscv64_reference(qemu_start_binary):
    qemu_start_binary(REFERENCE_BINARY, "riscv64")
    try:
        gdb.execute("break 4")
        assert pwndbg.gdblib.symbol.address("main") == 0x7FFFF7FBA668
        gdb.execute("continue")

        gdb.execute("stepuntilasm jalr")

        # verify call argument are enriched
        assembly = gdb.execute("nearpc", to_string=True)
        assert "'Not enough args'" in assembly

        gdb.execute("stepuntilasm c.jalr")

        # verify jump target is correct
        assembly = gdb.execute("nearpc 0", to_string=True)
        target = assembly.splitlines()[0].split()[-1]
        gdb.execute("stepi")
        assembly = gdb.execute("nearpc 0", to_string=True)
        assert assembly.split()[2] == target, (assembly.split()[2], target)

    except AssertionError:
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
