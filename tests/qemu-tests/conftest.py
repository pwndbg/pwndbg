"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys
from typing import Literal

import gdb
import pytest
from pwn import context
from pwn import make_elf_from_assembly
from pwn import pwnlib

_start_binary_called = False

QEMU_PORT = os.environ.get("QEMU_PORT")


@pytest.fixture
def qemu_assembly_run():
    """
    Returns function that launches given binary with 'starti' command

    The `path` is returned from `make_elf_from_assembly` (provided by pwntools)
    """

    qemu: subprocess.Popen = None

    if QEMU_PORT is None:
        print("'QEMU_PORT' environment variable not set")
        sys.exit(1)

    def _start_binary(asm: str, arch: str, endian: Literal["big", "little"] | None = None):
        nonlocal qemu

        # Clear the context so setting the .arch will also set .bits
        # https://github.com/Gallopsled/pwntools/issues/2498
        context.clear()
        context.arch = arch

        if endian is not None:
            context.endian = endian

        binary_tmp_path = make_elf_from_assembly(asm)
        qemu_suffix = pwnlib.qemu.archname()

        qemu = subprocess.Popen(
            [
                f"qemu-{qemu_suffix}",
                "-g",
                f"{QEMU_PORT}",
                f"{binary_tmp_path}",
            ]
        )

        os.environ["PWNDBG_IN_TEST"] = "1"
        os.environ["COLUMNS"] = "80"
        gdb.execute("set exception-verbose on")
        gdb.execute("set context-reserve-lines never")
        gdb.execute("set width 80")
        gdb.execute(f"target remote :{QEMU_PORT}")

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary

    qemu.kill()


# Map of qemu_suffix to location of library files in default Ubuntu installs of cross-compilers
CROSS_ARCH_LIBC = {
    "aarch64": "/usr/aarch64-linux-gnu",
    "arm": "/usr/arm-linux-gnueabihf",
    "mips": "/usr/mips-linux-gnu",
    "mipsel": "/usr/mipsel-linux-gnu",
    "mips64": "/usr/mips64-linux-gnuabi64/",
    "riscv64": "/usr/riscv64-linux-gnu/",
    "loongarch64": "/usr/loongarch64-linux-gnu/",
    "ppc": "/usr/powerpc-linux-gnu/",
    "ppc64": "/usr/powerpc64-linux-gnu/",
    "sparc64": "/usr/sparc64-linux-gnu/",
}


@pytest.fixture
def qemu_start_binary():
    """
    Returns function that launches given binary with 'starti' command

    Argument `path` is the path to the binary
    """

    qemu: subprocess.Popen = None

    if QEMU_PORT is None:
        print("'QEMU_PORT' environment variable not set")
        sys.exit(1)

    def _start_binary(path: str, arch: str, endian: Literal["big", "little"] | None = None):
        nonlocal qemu

        if endian is not None:
            context.endian = endian

        qemu_suffix = pwnlib.qemu.archname(arch=arch)
        # qemu_libs = pwnlib.qemu.ld_prefix(arch=arch)
        qemu_libs = CROSS_ARCH_LIBC.get(qemu_suffix, f"/usr/gnemul/qemu-{qemu_suffix}")

        assert os.path.isdir(qemu_libs), f"Cannot find cross-arch libraries at path: {qemu_libs}"

        qemu = subprocess.Popen(
            [
                f"qemu-{qemu_suffix}",
                "-L",
                qemu_libs,
                "-g",
                f"{QEMU_PORT}",
                f"{path}",
            ]
        )

        os.environ["PWNDBG_IN_TEST"] = "1"
        os.environ["COLUMNS"] = "80"
        gdb.execute("set exception-verbose on")
        gdb.execute("set context-reserve-lines never")
        gdb.execute("set width 80")
        gdb.execute(f"target remote :{QEMU_PORT}")

        global _start_binary_called
        # if _start_binary_called:
        #     raise Exception('Starting more than one binary is not supported in pwndbg tests.')

        _start_binary_called = True

    yield _start_binary

    qemu.kill()
