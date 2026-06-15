from __future__ import annotations

import os

from pwndbg.lib.proc_fd import Pipe
from pwndbg.lib.proc_fd import _read_fdinfo_mode
from pwndbg.lib.proc_fd import find_pipe_endpoints


def _pipe_inode(fd: int) -> int:
    return os.stat(f"/proc/self/fd/{fd}").st_ino


def test_find_pipe_endpoints_locates_both_ends() -> None:
    # An anonymous pipe(2) gives us a read end and a write end that share
    # the same inode but have different access modes. find_pipe_endpoints
    # must report both, with the correct read/write tag for each.
    r, w = os.pipe()
    try:
        inode = _pipe_inode(r)
        assert _pipe_inode(w) == inode

        endpoints = find_pipe_endpoints({inode})
        assert inode in endpoints
        ends = endpoints[inode]
        assert len(ends) >= 2

        modes = {fd: mode for (pid, fd, _comm, mode) in ends if pid == os.getpid()}
        assert modes[r] == "r"
        assert modes[w] == "w"
    finally:
        os.close(r)
        os.close(w)


def test_find_pipe_endpoints_empty_input() -> None:
    assert find_pipe_endpoints(set()) == {}


def test_find_pipe_endpoints_unknown_inode() -> None:
    # A made-up inode that nothing holds should simply be missing from the
    # result, not raise.
    assert find_pipe_endpoints({2**32 - 1}) == {}


def test_read_fdinfo_mode_for_pipe_ends() -> None:
    r, w = os.pipe()
    try:
        assert _read_fdinfo_mode(os.getpid(), r) == "r"
        assert _read_fdinfo_mode(os.getpid(), w) == "w"
    finally:
        os.close(r)
        os.close(w)


def test_read_fdinfo_mode_unknown_fd() -> None:
    # A wildly-invalid fd number gives us '?' instead of raising.
    assert _read_fdinfo_mode(os.getpid(), 999_999) == "?"


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
