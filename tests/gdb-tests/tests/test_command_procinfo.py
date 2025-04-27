from __future__ import annotations

import socket
import threading
import time

import gdb

import pwndbg.aglib.proc
import tests

REFERENCE_BINARY_NET = tests.binaries.get("reference-binary-net.out")


class TCPServerThread(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 31337))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(1)

    def run(self):
        try:
            # Accept one conn and sleep
            conn, addr = self.sock.accept()
            while True:
                time.sleep(1)
        except OSError:
            pass  # Socket closed


def test_command_procinfo(start_binary):
    start_binary(REFERENCE_BINARY_NET)

    # Listen tcp server
    server = TCPServerThread()
    server.start()

    bin_path = pwndbg.aglib.proc.exe
    pid = str(pwndbg.aglib.proc.pid)

    gdb.execute("break break_here")
    gdb.execute("continue")

    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[3]
    assert f"127.0.0.1:{server.port}" in result

    # Close tcp server
    server.sock.close()


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
