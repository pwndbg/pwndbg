from __future__ import annotations

import socket
import threading
import time

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY_NET = get_binary("reference-binary-net.native.out")
REFERENCE_BINARY_NETLINK = get_binary("reference-binary-netlink.native.out")
REFERENCE_BINARY_SOCKETPAIR = get_binary("reference-binary-socketpair.native.out")
REFERENCE_BINARY_PIPE = get_binary("reference-binary-pipe.native.out")


class TCPServerThread(threading.Thread):
    def __init__(self, *, ip: str, port: int):
        super().__init__(daemon=True)
        self.sock = socket.socket(
            socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM
        )
        try:
            self.sock.bind((ip, port))
        except OSError:
            pytest.skip(f"Could not bind to {ip}:{port}.")
        self.port = self.sock.getsockname()[1]
        self.sock.listen(1)

    def stop(self):
        self.sock.close()

    def run(self):
        try:
            # Accept one conn and sleep
            conn, addr = self.sock.accept()
            while True:
                time.sleep(1)
        except OSError:
            pass  # Socket closed


@pwndbg_test
@pytest.mark.parametrize("ip_connect", ["127.0.0.1", "::1"])
async def test_command_procinfo_net(ctrl: Controller, ip_connect: str) -> None:
    import pwndbg.aglib.proc

    # Listen tcp server
    server = TCPServerThread(ip=ip_connect, port=0)
    server.start()

    await ctrl.launch(REFERENCE_BINARY_NET, args=[ip_connect, str(server.port)])

    bin_path = pwndbg.aglib.proc.exe()
    pid = str(pwndbg.aglib.proc.pid())

    break_at_sym("break_here")
    await ctrl.cont()

    result = await ctrl.execute_and_capture("procinfo")
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[3]

    if ":" in ip_connect:
        assert f"[{ip_connect}]:{server.port}" in result
    else:
        assert f"{ip_connect}:{server.port}" in result

    # Close tcp server
    server.stop()


@pwndbg_test
async def test_command_procinfo_netlink(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY_NETLINK)

    break_at_sym("break_here")
    await ctrl.cont()

    result = await ctrl.execute_and_capture("procinfo")

    # The reference binary opens a NETLINK_ROUTE socket bound to
    # RTMGRP_LINK | RTMGRP_IPV4_IFADDR. procinfo should decode the
    # protocol family and the well-known group bits.
    assert "socket:NETLINK_ROUTE" in result
    assert "RTMGRP_LINK" in result
    assert "RTMGRP_IPV4_IFADDR" in result
    assert "inode=" in result
    assert "portid=" in result


@pwndbg_test
async def test_command_procinfo_unix_socketpair_peer(ctrl: Controller) -> None:
    import pwndbg.aglib.proc

    await ctrl.launch(REFERENCE_BINARY_SOCKETPAIR)

    break_at_sym("break_here")
    await ctrl.cont()

    pid = pwndbg.aglib.proc.pid()
    result = await ctrl.execute_and_capture("procinfo")

    # The reference binary creates a unix SOCK_STREAM socketpair, so we expect
    # two anonymous unix sockets in the FD list, each carrying peer info that
    # points back to the same process. SOCK_DIAG is local-only; this test
    # exercises the local code path on the test machine's kernel.
    anon_lines = [
        line for line in result.splitlines() if "unix '(anonymous)'" in line and "peer" in line
    ]
    assert len(anon_lines) == 2, f"expected 2 unix peer lines, got: {anon_lines}"

    for line in anon_lines:
        assert f"pid={pid}" in line
        assert "fd=" in line
        assert "inode=" in line


@pwndbg_test
async def test_command_procinfo_pipe(ctrl: Controller) -> None:
    import pwndbg.aglib.proc

    await ctrl.launch(REFERENCE_BINARY_PIPE)

    break_at_sym("break_here")
    await ctrl.cont()

    pid = pwndbg.aglib.proc.pid()
    result = await ctrl.execute_and_capture("procinfo")

    # The binary calls pipe(2), which gives us one read end and one write
    # end held by the same process. procinfo should label them as r/w and
    # show the same-process peer linkage. We can't pin to specific FDs
    # because the loader may shuffle them, so we look for the pair shape.
    pipe_lines = [
        line
        for line in result.splitlines()
        if line.lstrip().startswith("fd[") and "pipe:[" in line and "peers:" in line
    ]
    # The binary's own pipe(2) plus inherited stdio pipes from the test
    # harness can produce >2 lines; require at least one read/write pair
    # whose peer is in this process.
    own_lines = [line for line in pipe_lines if f"pid={pid}" in line]
    assert len(own_lines) >= 2, f"expected >=2 self-peering pipe lines, got: {pipe_lines}"

    has_read = any(" (r," in line for line in own_lines)
    has_write = any(" (w," in line for line in own_lines)
    assert has_read, f"no read end found: {own_lines}"
    assert has_write, f"no write end found: {own_lines}"
