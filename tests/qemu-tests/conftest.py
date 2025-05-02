"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

import os
import subprocess
import sys
import typing
from typing import Dict
from typing import Literal
from typing import Tuple

import gdb
import pytest

from pwndbg.lib import tempfile

_start_binary_called = False

QEMU_PORT = os.environ.get("QEMU_PORT")
ZIGPATH = os.environ.get("ZIGPATH")

COMPILATION_TARGETS_TYPE = Literal[
    "aarch64",
    "arm",
    "riscv32",
    "riscv64",
    "loongarch64",
    "powerpc32",
    "powerpc64",
    "mips32",
    "mipsel32",
    "mips64",
    "s390x",
    "sparc",
]

COMPILATION_TARGETS: list[COMPILATION_TARGETS_TYPE] = list(
    typing.get_args(COMPILATION_TARGETS_TYPE)
)

# Tuple contains (Zig target,extra_cli_args,qemu_suffix),
COMPILE_AND_RUN_INFO: Dict[COMPILATION_TARGETS_TYPE, Tuple[str, Tuple[str, ...], str]] = {
    "aarch64": ("aarch64-freestanding", (), "aarch64"),
    # TODO: when updating to newer version of Zig, this -mcpu option can be removed
    "arm": ("arm-freestanding", ("-mcpu=cortex_a7",), "arm"),
    "riscv32": ("riscv32-freestanding", (), "riscv32"),
    "riscv64": ("riscv64-freestanding", (), "riscv64"),
    "mips32": ("mips-freestanding", (), "mips"),
    "mipsel32": ("mipsel-freestanding", (), "mipsel"),
    "mips64": ("mips64-freestanding", (), "mips64"),
    "loongarch64": ("loongarch64-freestanding", (), "loongarch64"),
    "s390x": ("s390x-freestanding", (), "s390x"),
    "sparc": ("sparc64-freestanding", (), "sparc64"),
    "powerpc32": ("powerpc-freestanding", (), "ppc"),
    "powerpc64": ("powerpc64-freestanding", (), "ppc64"),
}


@pytest.fixture
def qemu_assembly_run():
    """
    Returns function that launches given binary with 'starti' command

    The `path` is returned from `make_elf_from_assembly` (provided by pwntools)
    """

    if ZIGPATH is None:
        raise Exception("ZIGPATH not defined")

    PATH_TO_ZIG = os.path.join(ZIGPATH, "zig")

    qemu: subprocess.Popen = None

    if QEMU_PORT is None:
        print("'QEMU_PORT' environment variable not set")
        sys.exit(1)

    def _start_binary(asm: str, arch: COMPILATION_TARGETS_TYPE):
        nonlocal qemu

        if arch not in COMPILATION_TARGETS or arch not in COMPILE_AND_RUN_INFO:
            raise Exception(f"Unknown compilation target: {arch}")

        zig_target, extra_cli_args, qemu_suffix = COMPILE_AND_RUN_INFO[arch]

        # Place assembly and compiled binary in a temporary folder
        # named /tmp/pwndbg-*
        tmpdir = tempfile.tempdir()

        asm_file = os.path.join(tmpdir, "input.S")

        with open(asm_file, "w") as f:
            f.write(asm)

        compiled_file = os.path.join(tmpdir, "out.elf")

        # Build the binary with Zig
        compile_process = subprocess.run(
            [
                PATH_TO_ZIG,
                "cc",
                *extra_cli_args,
                f"--target={zig_target}",
                asm_file,
                "-o",
                compiled_file,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )

        if compile_process.returncode != 0:
            raise Exception("Compilation error", compile_process.stdout, compile_process.stderr)

        qemu = subprocess.Popen(
            [
                f"qemu-{qemu_suffix}",
                "-g",
                f"{QEMU_PORT}",
                f"{compiled_file}",
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

    def _start_binary(path: str, arch: COMPILATION_TARGETS_TYPE):
        nonlocal qemu

        if arch not in COMPILATION_TARGETS or arch not in COMPILE_AND_RUN_INFO:
            raise Exception(f"Unknown compilation target: {arch}")

        _, _, qemu_suffix = COMPILE_AND_RUN_INFO[arch]

        qemu = subprocess.Popen(
            [
                f"qemu-{qemu_suffix}",
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
