from __future__ import annotations

import os
from typing import Literal

import gdb
import pytest
import user

import pwndbg.aglib.proc
import pwndbg.commands.context
import pwndbg.lib.arch

# The tests in this file execute for a long time - they can take 5-15 minutes to run, depending on the machine
# They check for any crashes in the instruction enhancement code that may arise through
# when displaying the context.
# These are worth running after large changes in the instruction enhancement code and updates to Unicorn/Capstone.

SKIP_SLOW_TESTS = os.getenv("PWNDBG_RUN_SLOW_TESTS") is not None

REASON_SKIPPING = (
    "Test skipped because it is slow - run these tests when changing instruction enhancement code"
)


# Step through a binary, running "ctx" each time the program stops
# This is meant to detect crashes originating from the annotations/emulation code
def helper(
    qemu_start_binary, filename: str, qemu_arch: str, endian: Literal["big", "little"] | None = None
):
    FILE = user.binaries.get(filename)

    qemu_start_binary(FILE, qemu_arch, endian)

    gdb.execute("b main")
    gdb.execute("c")

    pwndbg.commands.context.context()

    # Step through at least 10,000 instructions
    for i in range(10000):
        if not pwndbg.aglib.proc.alive:
            break
        gdb.execute("stepi")
        pwndbg.commands.context.context()


@pytest.mark.skipif(SKIP_SLOW_TESTS is False, reason=REASON_SKIPPING)
def test_basic_aarch64(qemu_start_binary):
    helper(qemu_start_binary, "basic.aarch64.out", "aarch64")


@pytest.mark.skipif(SKIP_SLOW_TESTS is False, reason=REASON_SKIPPING)
def test_basic_arm(qemu_start_binary):
    helper(qemu_start_binary, "basic.arm.out", "arm")


@pytest.mark.skipif(SKIP_SLOW_TESTS is False, reason=REASON_SKIPPING)
def test_basic_riscv64(qemu_start_binary):
    helper(qemu_start_binary, "basic.riscv64.out", "riscv64")


@pytest.mark.skipif(SKIP_SLOW_TESTS is False, reason=REASON_SKIPPING)
def test_basic_mips64(qemu_start_binary):
    # pwnlib.context.endian defaults to "little", but these MIPS binaries are compiled to big endian.
    helper(qemu_start_binary, "basic.mips64.out", "mips64", endian="big")


@pytest.mark.skipif(SKIP_SLOW_TESTS is False, reason=REASON_SKIPPING)
def test_basic_mips32(qemu_start_binary):
    helper(qemu_start_binary, "basic.mips32.out", "mips", endian="big")
