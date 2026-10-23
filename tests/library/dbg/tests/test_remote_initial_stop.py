from __future__ import annotations

import os
import re
import select
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

GDBSERVER = shutil.which("gdbserver")
CRASH_BINARY = get_binary("crash_simple.native.out")

pytestmark = pytest.mark.skipif(GDBSERVER is None, reason="gdbserver is not installed")


def _start_gdbserver(*args: str) -> tuple[subprocess.Popen[bytes], int]:
    assert GDBSERVER is not None
    process = subprocess.Popen(
        [GDBSERVER, *args], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    assert process.stderr is not None
    # With port 0 gdbserver picks a free port and announces it on stderr.
    stderr_fd = process.stderr.fileno()
    os.set_blocking(stderr_fd, False)
    seen = b""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if select.select([stderr_fd], [], [], deadline - time.monotonic())[0]:
            seen += os.read(stderr_fd, 4096)
        if match := re.search(rb"Listening on port (\d+)", seen):
            return process, int(match.group(1))
    process.kill()
    process.wait()
    pytest.fail(f"gdbserver did not report a listening port; stderr so far: {seen!r}")


def _rsp(sock: socket.socket, packet: bytes) -> bytes:
    sock.sendall(b"$%s#%02x" % (packet, sum(packet) & 0xFF))
    data = b""
    while not (match := re.search(rb"\$([^#]*)#..", data)):
        data += sock.recv(4096)
    sock.sendall(b"+")
    return match.group(1)


@pytest.fixture
def gdbserver_crashed() -> Iterator[int]:
    process, port = _start_gdbserver("--multi", "127.0.0.1:0")
    # Run the binary into its crash and drop the connection. gdbserver keeps the
    # inferior stopped on the signal for the next client.
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        _rsp(sock, b"vRun;" + str(CRASH_BINARY).encode().hex().encode())
        assert _rsp(sock, b"c").startswith(b"T04")  # SIGILL
    yield port
    process.kill()
    process.wait()


@pwndbg_test
async def test_remote_initial_real_signal(ctrl: Controller, gdbserver_crashed: int) -> None:
    """
    A remote inferior may already be stopped on a real signal when we connect.
    """
    import pwndbg

    port = gdbserver_crashed
    if pwndbg.dbg.is_gdblib_available():
        await ctrl.execute(f"file {CRASH_BINARY}")
        await ctrl.execute(f"target remote 127.0.0.1:{port}")
    else:
        await ctrl.execute(f"target create {CRASH_BINARY}")
        await ctrl.execute(f"gdb-remote 127.0.0.1:{port}")

    assert pwndbg.dbg.selected_inferior().stopped_with_signal()
