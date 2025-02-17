from __future__ import annotations
from typing import Literal

import gdb
import user

import pwndbg.aglib.proc
import pwndbg.commands.context
import pwndbg.lib.arch


# Step through a binary, running "ctx" each time the program stops
# This is meant to detect crashes originating from the annotations/emulation code
def helper(qemu_start_binary, filename: str, qemu_arch: str, endian: Literal["big","little"] | None = None):
    FILE = user.binaries.get(filename)

    qemu_start_binary(FILE, qemu_arch, endian)

    gdb.execute("b main")
    gdb.execute("c")

    pwndbg.commands.context.context()

    # Step through at least 10,000 instructions
    for i in range(10):
        if not pwndbg.aglib.proc.alive:
            break
        gdb.execute("stepi")
        pwndbg.commands.context.context()


def test_basic_aarch64(qemu_start_binary):
    helper(qemu_start_binary, "basic.aarch64.out", "aarch64")


def test_basic_arm(qemu_start_binary):
    helper(qemu_start_binary, "basic.arm.out", "arm")


def test_basic_riscv64(qemu_start_binary):
    helper(qemu_start_binary, "basic.riscv64.out", "riscv64")


def test_basic_mips64(qemu_start_binary):
    # pwnlib.context.endian defaults to "little", but these MIPS binaries are compiled to big endian.
    helper(qemu_start_binary, "basic.mips64.out", "mips64",endian="big")


def test_basic_mips32(qemu_start_binary):
    helper(qemu_start_binary, "basic.mips32.out", "mips", endian="big")
