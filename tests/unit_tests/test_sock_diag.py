from __future__ import annotations

import os
import socket

from pwndbg.lib.sock_diag import find_socket_inode_owners
from pwndbg.lib.sock_diag import get_unix_peers


def _socket_inode(fd: int) -> int:
    return os.stat(f"/proc/self/fd/{fd}").st_ino


def test_get_unix_peers_resolves_socketpair() -> None:
    # socketpair() is the easiest way to materialize a connected unix pair
    # the kernel knows about. Each end's inode should map to the other end's.
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ino_a = _socket_inode(a.fileno())
        ino_b = _socket_inode(b.fileno())
        assert ino_a != ino_b

        peers = get_unix_peers()
        assert peers.get(ino_a) == ino_b
        assert peers.get(ino_b) == ino_a
    finally:
        a.close()
        b.close()


def test_get_unix_peers_after_close() -> None:
    # Closing one end of the pair makes the kernel forget the peer mapping
    # for the still-open end. We don't promise the entry vanishes, but it
    # must not point to a stale inode that's been reused.
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    ino_b = _socket_inode(b.fileno())
    a.close()
    try:
        peers = get_unix_peers()
        # The remaining socket may still appear, but its peer should be gone
        # or at least not the inode of the closed end.
        assert peers.get(ino_b) != ino_b
    finally:
        b.close()


def test_find_socket_inode_owners_locates_self() -> None:
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        ino_a = _socket_inode(a.fileno())
        ino_b = _socket_inode(b.fileno())

        owners = find_socket_inode_owners({ino_a, ino_b})
        assert ino_a in owners
        assert ino_b in owners

        pid_a, fd_a, _comm_a = owners[ino_a]
        pid_b, fd_b, _comm_b = owners[ino_b]
        assert pid_a == os.getpid()
        assert pid_b == os.getpid()
        assert fd_a == a.fileno()
        assert fd_b == b.fileno()
    finally:
        a.close()
        b.close()


def test_find_socket_inode_owners_empty_input() -> None:
    assert find_socket_inode_owners(set()) == {}


def test_find_socket_inode_owners_unknown_inode() -> None:
    # An inode that no process has open should simply be absent from the
    # returned dict, not raise.
    assert find_socket_inode_owners({2**32 - 1}) == {}
