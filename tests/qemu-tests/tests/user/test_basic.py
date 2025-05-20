from __future__ import annotations

import gdb
import user

import pwndbg.aglib.proc
import pwndbg.commands.context

# The tests in this file execute for a long time - they can take 5-15 minutes to run, depending on the machine
# They check for any crashes in the instruction enhancement code that may arise through
# when displaying the context.
# These are worth running after large changes in the instruction enhancement code and updates to Unicorn/Capstone.

NUMBER_OF_STEPS = 1500


# Step through a binary, running "ctx" each time the program stops
# This is meant to detect crashes originating from the annotations/emulation code
def helper(qemu_start_binary, filename: str, arch: str):
    FILE = user.binaries.get(filename)

    qemu_start_binary(FILE, arch)

    pwndbg.commands.context.context_disasm()

    for i in range(NUMBER_OF_STEPS):
        if not pwndbg.aglib.proc.alive:
            break
        gdb.execute("stepi")
        pwndbg.commands.context.context_disasm()


def test_basic_aarch64(qemu_start_binary):
    helper(qemu_start_binary, "basic.aarch64.out", "aarch64")


def test_basic_arm(qemu_start_binary):
    helper(qemu_start_binary, "basic.arm.out", "arm")


def test_basic_riscv64(qemu_start_binary):
    helper(qemu_start_binary, "basic.riscv64.out", "riscv64")


def test_basic_mips64(qemu_start_binary):
    # pwnlib.context.endian defaults to "little", but these MIPS binaries are compiled to big endian.
    helper(qemu_start_binary, "basic.mips64.out", "mips64")


def test_basic_mips32(qemu_start_binary):
    helper(qemu_start_binary, "basic.mips32.out", "mips32")


def test_basic_mipsel32(qemu_start_binary):
    helper(qemu_start_binary, "basic.mipsel32.out", "mipsel32")
