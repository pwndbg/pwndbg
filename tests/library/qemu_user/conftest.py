"""
This file should consist of global test fixtures.
"""

from __future__ import annotations

import os
import subprocess
import typing
from typing import Dict
from typing import Literal
from typing import Tuple

import gdb
import pytest
import ziglang

from pwndbg.lib import tempfile

_start_binary_called = False

QEMU_PORT: str | None = None

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
    "arm": ("arm-freestanding", (), "arm"),
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


def reserve_port(ip: str = "127.0.0.1", port: int = 0) -> str:
    """
    https://github.com/Yelp/ephemeral-port-reserve/blob/master/ephemeral_port_reserve.py

    Bind to an ephemeral port, force it into the TIME_WAIT state, and unbind it.

    This means that further ephemeral port alloctions won't pick this "reserved" port,
    but subprocesses can still bind to it explicitly, given that they use SO_REUSEADDR.
    By default on linux you have a grace period of 60 seconds to reuse this port.
    To check your own particular value:
    $ cat /proc/sys/net/ipv4/tcp_fin_timeout
    60

    By default, the port will be reserved for localhost (aka 127.0.0.1).
    To reserve a port for a different ip, provide the ip as the first argument.
    Note that IP 0.0.0.0 is interpreted as localhost.
    """
    import contextlib
    import errno
    from socket import SO_REUSEADDR
    from socket import SOL_SOCKET
    from socket import error as SocketError
    from socket import socket

    port = int(port)
    with contextlib.closing(socket()) as s:
        s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        try:
            s.bind((ip, port))
        except SocketError as e:
            # socket.error: EADDRINUSE Address already in use
            if e.errno == errno.EADDRINUSE and port != 0:
                s.bind((ip, 0))
            else:
                raise

        # the connect below deadlocks on kernel >= 4.4.0 unless this arg is greater than zero
        s.listen(1)

        sockname = s.getsockname()

        # these three are necessary just to get the port into a TIME_WAIT state
        with contextlib.closing(socket()) as s2:
            s2.connect(sockname)
            sock, _ = s.accept()
            with contextlib.closing(sock):
                return sockname[1]


def ensure_qemu_port():
    """
    Ensures that QEMU_PORT is set to a valid, usable port.
    """
    global QEMU_PORT
    if QEMU_PORT is None:
        QEMU_PORT = reserve_port()
        print(f"Reserved port {QEMU_PORT} for QEMU")


@pytest.fixture
def qemu_assembly_run():
    """
    Returns function that launches given binary with 'starti' command

    The `path` is returned from `make_elf_from_assembly` (provided by pwntools)
    """

    ensure_qemu_port()

    qemu: subprocess.Popen = None

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
                os.path.join(os.path.dirname(ziglang.__file__), "zig"),
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

    ensure_qemu_port()

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
