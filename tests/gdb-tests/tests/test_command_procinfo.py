from __future__ import annotations

import socket
import threading
import time

import gdb
import pytest

import pwndbg.aglib.proc
import tests

REFERENCE_BINARY_NET = tests.binaries.get("reference-binary-net.out")


class TCPServerThread(threading.Thread):
    def __init__(self, *, ip: str, port: int):
        super().__init__(daemon=True)
        self.sock = socket.socket(
            socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM
        )
        self.sock.bind((ip, port))
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


@pytest.mark.parametrize("ip_connect", ["127.0.0.1", "::1"])
def test_command_procinfo_net(start_binary, ip_connect):
    # Listen tcp server
    server = TCPServerThread(ip=ip_connect, port=0)
    server.start()

    start_binary(REFERENCE_BINARY_NET, ip_connect, str(server.port))

    bin_path = pwndbg.aglib.proc.exe
    pid = str(pwndbg.aglib.proc.pid)

    gdb.execute("break break_here")
    gdb.execute("continue")

    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[3]

    if ":" in ip_connect:
        assert f"[{ip_connect}]:{server.port}" in result
    else:
        assert f"{ip_connect}:{server.port}" in result

    # Close tcp server
    server.stop()


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
