from __future__ import annotations

import os

from pwndbg.lib.proc_fd import Pipe
from pwndbg.lib.proc_fd import find_pipe_endpoints
from pwndbg.lib.proc_fd import parse_fdinfo_mode
from pwndbg.lib.proc_fd import pipe_endpoints_from_fd_rows


def _pipe_inode(fd: int) -> int:
    return os.stat(f"/proc/self/fd/{fd}").st_ino


def _live_fdinfo_mode(fd: int) -> str:
    with open(f"/proc/self/fdinfo/{fd}") as f:
        return parse_fdinfo_mode(f.read())


def test_find_pipe_endpoints_locates_both_ends() -> None:
    # An anonymous pipe(2) gives us a read end and a write end that share
    # the same inode. find_pipe_endpoints must report both FDs.
    r, w = os.pipe()
    try:
        inode = _pipe_inode(r)
        assert _pipe_inode(w) == inode

        endpoints = find_pipe_endpoints({inode})
        assert inode in endpoints
        ends = endpoints[inode]
        assert len(ends) >= 2

        own_fds = {fd for (pid, fd, _comm) in ends if pid == os.getpid()}
        assert {r, w} <= own_fds
    finally:
        os.close(r)
        os.close(w)


def test_find_pipe_endpoints_empty_input() -> None:
    assert find_pipe_endpoints(set()) == {}


def test_find_pipe_endpoints_unknown_inode() -> None:
    # A made-up inode that nothing holds should simply be missing from the
    # result, not raise.
    assert find_pipe_endpoints({2**32 - 1}) == {}


def test_parse_fdinfo_mode_on_live_pipe_ends() -> None:
    # The parser against real kernel-produced fdinfo text, not a fixture.
    r, w = os.pipe()
    try:
        assert _live_fdinfo_mode(r) == "r"
        assert _live_fdinfo_mode(w) == "w"
    finally:
        os.close(r)
        os.close(w)


def test_pipe_endpoints_from_fd_rows() -> None:
    # Rows in the shape of the remote stub's "files" osdata table: the same
    # pipe held by two processes, plus unrelated FDs that must be ignored.
    rows = [
        (4243, 0, "grep", "pipe:[555]"),
        (4242, 4, "cat", "pipe:[555]"),
        (4242, 1, "cat", "/dev/pts/0"),
        (9999, 3, "other", "pipe:[777]"),
        (1, 5, "init", "socket:[555]"),
    ]
    endpoints = pipe_endpoints_from_fd_rows(rows, {555})
    assert set(endpoints) == {555}
    # Sorted by (pid, fd).
    assert endpoints[555] == [(4242, 4, "cat"), (4243, 0, "grep")]


def test_pipe_endpoints_from_fd_rows_malformed_names() -> None:
    rows = [
        (1, 2, "x", "pipe:[notanumber]"),
        (1, 3, "x", "pipe:[123"),
        (1, 4, "x", ""),
    ]
    assert pipe_endpoints_from_fd_rows(rows, {123}) == {}


def test_parse_fdinfo_mode() -> None:
    # This is the parser used for remote targets, where fdinfo arrives as bytes
    # over vFile rather than being read from the local procfs.
    fdinfo = "pos:\t0\nflags:\t02\nmnt_id:\t14\nino:\t1109875\n"
    assert parse_fdinfo_mode(fdinfo) == "rw"
    assert parse_fdinfo_mode("pos:\t0\nflags:\t00\n") == "r"
    assert parse_fdinfo_mode("pos:\t0\nflags:\t0100001\n") == "w"


def test_parse_fdinfo_mode_malformed() -> None:
    # No flags line, an empty value, or a non-octal value: '?' rather than raise.
    assert parse_fdinfo_mode("") == "?"
    assert parse_fdinfo_mode("pos:\t0\nino:\t123\n") == "?"
    assert parse_fdinfo_mode("flags:\t\n") == "?"
    assert parse_fdinfo_mode("flags:\tnonsense\n") == "?"


def test_pipe_str_renders_self_only() -> None:
    p = Pipe()
    p.inode = 12345
    p.fd = 3
    p.mode = "r"
    # No peers (e.g., the other end has been closed): we still render mode.
    assert str(p) == "pipe:[12345] (r)"


def test_pipe_str_renders_peer() -> None:
    p = Pipe()
    p.inode = 12345
    p.fd = 3
    p.mode = "r"
    p.peers = [(4242, 7, "writer", "w")]
    s = str(p)
    assert "pipe:[12345]" in s
    assert "r" in s
    assert "pid=4242" in s
    assert "'writer'" in s
    assert "fd=7" in s
    assert "w" in s


def test_pipe_str_renders_multiple_peers() -> None:
    p = Pipe()
    p.inode = 12345
    p.fd = 3
    p.mode = "r"
    p.peers = [(100, 4, "a", "w"), (200, 5, "b", "w")]
    s = str(p)
    assert "pid=100" in s
    assert "pid=200" in s
    # The two peers are joined by "; " so both end up on one line.
    assert s.count(";") == 1
