from __future__ import annotations

import os
import socket
import tempfile
import threading
import time

import gdb
import pytest

from . import get_binary

REFERENCE_BINARY = get_binary("reference-binary.out")
USE_FDS_BINARY = get_binary("use-fds.out")


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
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()
        self.sock.close()

    def run(self):
        try:
            # Accept one conn and wait for stop event
            conn, addr = self.sock.accept()
            while not self.stop_event.is_set():
                time.sleep(0.1)
        except OSError:
            pass  # Socket closed


class UDPServerThread(threading.Thread):
    def __init__(self, *, ip: str, port: int):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((ip, port))
        except OSError:
            pytest.skip(f"Could not bind UDP to {ip}:{port}.")
        self.port = self.sock.getsockname()[1]
        self.received_data = None

    def stop(self):
        self.sock.close()

    def run(self):
        try:
            # Wait for data with timeout
            self.sock.settimeout(1)
            data, addr = self.sock.recvfrom(1024)
            self.received_data = data
        except socket.timeout:
            pass
        except OSError:
            pass


def test_hijack_fd_file_redirection(start_binary):
    """
    Test hijack_fd command with file redirection
    """
    start_binary(REFERENCE_BINARY)

    # Create a temporary file for testing
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file.write("test content for hijack_fd")
        temp_file_path = temp_file.name

    try:
        # Run until break_here
        gdb.execute("xuntil &break_here")

        # Hijack stdout (fd 1) to point to our temporary file
        result = gdb.execute(f"hijack-fd 1 {temp_file_path}", to_string=True)
        assert "Operation succeeded" in result

        # Actually write to the hijacked file descriptor to validate it works
        gdb.execute('call write(1, "hello\\n", 6)')

        # Check the file content to verify the write went to our file
        with open(temp_file_path, "r") as f:
            content = f.read()
            assert "hello" in content

        # Verify the file descriptor change using procinfo
        final_procinfo = gdb.execute("procinfo", to_string=True)

        # Check that fd[1] now points to our temporary file
        assert temp_file_path in final_procinfo

    finally:
        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


@pytest.mark.parametrize("ip_connect", ["127.0.0.1", "::1"])
def test_hijack_fd_socket_redirection(start_binary, ip_connect):
    """
    Test hijack_fd command with TCP socket redirection (IPv4 and IPv6)
    """
    # Start TCP server
    server = TCPServerThread(ip=ip_connect, port=0)
    server.start()

    try:
        start_binary(REFERENCE_BINARY)

        gdb.execute("xuntil break_here")

        # Use URI style for IPv6, plain for IPv4
        if ":" in ip_connect:
            uri = f"tcp://[{ip_connect}]:{server.port}"
        else:
            uri = f"{ip_connect}:{server.port}"

        result = gdb.execute(f"hijack-fd 2 {uri}", to_string=True)
        assert "Operation succeeded" in result

        # Verify the file descriptor change using procinfo
        final_procinfo = gdb.execute("procinfo", to_string=True)

        # Check that fd[2] now shows a socket connection
        if ":" in ip_connect:
            assert f"[{ip_connect}]:{server.port}" in final_procinfo
        else:
            assert f"{ip_connect}:{server.port}" in final_procinfo

    finally:
        server.stop()
        server.join(timeout=2)  # Wait for thread to finish


def test_hijack_fd_udp_socket_redirection(start_binary):
    """
    Test hijack_fd command with UDP socket redirection
    """
    # Start UDP server
    server = UDPServerThread(ip="127.0.0.1", port=0)
    server.start()

    try:
        start_binary(REFERENCE_BINARY)

        gdb.execute("xuntil break_here")

        # Hijack stderr (fd 2) to point to our UDP socket
        result = gdb.execute(f"hijack-fd 2 udp://127.0.0.1:{server.port}", to_string=True)
        assert "Operation succeeded" in result

        # Verify the file descriptor change using procinfo
        final_procinfo = gdb.execute("procinfo", to_string=True)

        # Check that fd[2] is now a socket (UDP sockets may not show IP:port in procinfo)
        # The important thing is that it's a socket, not the original stderr
        assert "socket:" in final_procinfo

        # Verify that fd[2] specifically is not pointing to /dev/pts/ (original stderr)
        # We need to check that the line containing fd[2] doesn't contain /dev/pts/
        lines = final_procinfo.split("\n")
        fd2_line = None
        for line in lines:
            if line.strip().startswith("fd[2]"):
                fd2_line = line
                break

        assert fd2_line is not None, "fd[2] not found in procinfo output"
        assert "/dev/pts/" not in fd2_line, f"fd[2] still points to /dev/pts/: {fd2_line}"

    finally:
        server.stop()
        server.join(timeout=2)  # Wait for thread to finish


def test_hijack_fd_invalid_fd(start_binary):
    """
    Test hijack_fd command with invalid file descriptor
    """
    start_binary(REFERENCE_BINARY)

    # Run until break_here
    gdb.execute("xuntil break_here")

    # Try to hijack an invalid file descriptor (negative number)
    result = gdb.execute("hijack-fd -1 /dev/null", to_string=True)
    # The command should execute but may not work as expected
    # We verify it doesn't crash and returns some response
    assert result is not None


def test_hijack_fd_nonexistent_file(start_binary):
    """
    Test hijack_fd command with nonexistent file
    """
    start_binary(REFERENCE_BINARY)

    gdb.execute("xuntil break_here")

    # Use a path that can be created without root permissions
    test_file_path = "/tmp/nonexistent_test_file"

    # Try to hijack to a nonexistent file
    result = gdb.execute(f"hijack-fd 1 {test_file_path}", to_string=True)
    # The command should succeed in creating the file descriptor,
    # even if the file doesn't exist initially
    assert "Operation succeeded" in result

    # Verify the file was actually created
    assert os.path.exists(test_file_path)

    # Clean up
    if os.path.exists(test_file_path):
        os.unlink(test_file_path)


def test_hijack_fd_invalid_socket_address(start_binary):
    """
    Test hijack_fd command with invalid socket address
    """
    start_binary(REFERENCE_BINARY)

    gdb.execute("xuntil break_here")

    # Try to hijack to an invalid socket address
    result = gdb.execute("hijack-fd 2 invalid://address:port", to_string=True)
    # The command should handle the error gracefully
    # We verify it doesn't crash the debugger and returns some response
    assert result is not None


def test_hijack_fd_before_binary_start():
    """
    Test hijack_fd command before binary is started
    """
    # Try to use hijack_fd before starting any binary
    result = gdb.execute("hijack-fd 1 /dev/null", to_string=True)
    assert "The program is not being run" in result


def test_hijack_fd_help():
    """
    Test hijack_fd command help
    """
    result = gdb.execute("hijack-fd --help", to_string=True)
    assert "usage: hijack-fd" in result
    assert "Replace a file descriptor" in result
    assert "fdnum" in result
    assert "newfile" in result


def test_hijack_fd_with_use_fds_binary(start_binary):
    """
    Test hijack_fd command with the use-fds binary which opens a file
    """
    start_binary(USE_FDS_BINARY)

    # Run until main
    gdb.execute("start")

    # Stop after the open() call
    gdb.execute("nextcall")
    gdb.execute("nextcall")

    # Get the file descriptor number
    fd_var = gdb.newest_frame().read_var("fd")
    fd_num = int(fd_var)

    # Create a temporary file for testing
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as temp_file:
        temp_file.write("hijacked content")
        temp_file_path = temp_file.name

    try:
        # Hijack the opened file descriptor to our temporary file
        result = gdb.execute(f"hijack-fd {fd_num} {temp_file_path}", to_string=True)
        assert "Operation succeeded" in result

        # Verify the file descriptor change using procinfo
        final_procinfo = gdb.execute("procinfo", to_string=True)

        # Check that the hijacked fd now points to our temporary file
        assert temp_file_path in final_procinfo

    finally:
        # Clean up temporary file
        if os.path.exists(temp_file_path):
            os.unlink(temp_file_path)
