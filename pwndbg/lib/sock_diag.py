"""
Lightweight wrapper around the kernel SOCK_DIAG netlink subsystem.

Right now we only expose the unix-domain peer lookup, which procinfo uses to
turn an anonymous unix socket FD into a "this end is connected to PID X" line.
There is no /proc file that exposes peer information, so this can only run
against the *local* kernel: callers must skip it for remote / cross-machine
debugging targets.
"""

from __future__ import annotations

import os
import socket
import struct

# Netlink + SOCK_DIAG protocol constants. These are stable kernel ABI values
# from <linux/netlink.h> and <linux/sock_diag.h> / <linux/unix_diag.h>; we
# re-declare them here so we don't depend on socket module additions in newer
# Python versions.
_NETLINK_SOCK_DIAG = 4
_SOCK_DIAG_BY_FAMILY = 20

_NLM_F_REQUEST = 0x1
_NLM_F_ROOT = 0x100
_NLM_F_MATCH = 0x200
_NLM_F_DUMP = _NLM_F_ROOT | _NLM_F_MATCH

_NLMSG_ERROR = 2
_NLMSG_DONE = 3

_AF_UNIX = 1
_UDIAG_SHOW_PEER = 0x4
# enum unix_diag_attrs: UNIX_DIAG_NAME=0, UNIX_DIAG_VFS=1, UNIX_DIAG_PEER=2, ...
_UNIX_DIAG_PEER = 2

_NLMSG_HDR_FMT = "IHHII"  # len, type, flags, seq, pid
_NLMSG_HDR_SIZE = struct.calcsize(_NLMSG_HDR_FMT)

# struct unix_diag_req: u8 family, u8 protocol, u16 pad, u32 states, u32 ino,
#                      u32 show, u32 cookie[2]
_UNIX_DIAG_REQ_FMT = "BBHIIIII"
_UNIX_DIAG_REQ_SIZE = struct.calcsize(_UNIX_DIAG_REQ_FMT)

# struct unix_diag_msg: u8 family, u8 type, u8 state, u8 pad, u32 ino,
#                      u32 cookie[2]
_UNIX_DIAG_MSG_FMT = "BBBBIII"
_UNIX_DIAG_MSG_SIZE = struct.calcsize(_UNIX_DIAG_MSG_FMT)


def _nlmsg_align(length: int) -> int:
    return (length + 3) & ~3


def get_unix_peers() -> dict[int, int]:
    """Return ``{inode: peer_inode}`` for unix sockets on the local kernel.

    Sockets without a peer (e.g. listening or unconnected) are simply absent
    from the returned mapping. Returns an empty dict if the kernel doesn't
    speak NETLINK_SOCK_DIAG, if we lack permission, or if anything goes wrong
    while parsing — callers should treat the absence of an entry as "unknown",
    not as "no peer".
    """
    try:
        sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, _NETLINK_SOCK_DIAG)
    except OSError:
        return {}

    try:
        sock.settimeout(2.0)

        # Dump every unix socket regardless of state, asking the kernel to
        # include the peer attribute. ino=0 with NLM_F_DUMP means "all".
        diag_req = struct.pack(
            _UNIX_DIAG_REQ_FMT,
            _AF_UNIX,
            0,
            0,
            0xFFFFFFFF,  # all states
            0,  # ino: 0 = dump all
            _UDIAG_SHOW_PEER,
            0xFFFFFFFF,
            0xFFFFFFFF,  # cookie ~0
        )
        nlmsg_len = _NLMSG_HDR_SIZE + _UNIX_DIAG_REQ_SIZE
        request = (
            struct.pack(
                _NLMSG_HDR_FMT,
                nlmsg_len,
                _SOCK_DIAG_BY_FAMILY,
                _NLM_F_REQUEST | _NLM_F_DUMP,
                1,  # seq
                0,  # pid (kernel)
            )
            + diag_req
        )

        try:
            sock.send(request)
        except OSError:
            return {}

        peers: dict[int, int] = {}
        done = False
        while not done:
            try:
                data = sock.recv(65536)
            except OSError:
                break
            if not data:
                break

            offset = 0
            while offset + _NLMSG_HDR_SIZE <= len(data):
                msg_len, msg_type, _flags, _seq, _pid = struct.unpack_from(
                    _NLMSG_HDR_FMT, data, offset
                )
                if msg_len < _NLMSG_HDR_SIZE or offset + msg_len > len(data):
                    done = True
                    break
                if msg_type in (_NLMSG_DONE, _NLMSG_ERROR):
                    done = True
                    break
                if msg_type == _SOCK_DIAG_BY_FAMILY:
                    _peers_from_msg(data, offset + _NLMSG_HDR_SIZE, offset + msg_len, peers)

                offset += _nlmsg_align(msg_len)

        return peers
    finally:
        sock.close()


def _peers_from_msg(buf: bytes, msg_start: int, msg_end: int, out: dict[int, int]) -> None:
    if msg_start + _UNIX_DIAG_MSG_SIZE > msg_end:
        return
    _family, _type, _state, _pad, inode, _c0, _c1 = struct.unpack_from(
        _UNIX_DIAG_MSG_FMT, buf, msg_start
    )

    # struct nlattr: u16 nla_len, u16 nla_type
    attr_offset = msg_start + _UNIX_DIAG_MSG_SIZE
    while attr_offset + 4 <= msg_end:
        attr_len, attr_type = struct.unpack_from("HH", buf, attr_offset)
        if attr_len < 4 or attr_offset + attr_len > msg_end:
            return
        if attr_type == _UNIX_DIAG_PEER and attr_len >= 8:
            (peer_inode,) = struct.unpack_from("I", buf, attr_offset + 4)
            if peer_inode:
                out[inode] = peer_inode
        attr_offset += _nlmsg_align(attr_len)


def find_socket_inode_owners(inodes: set[int]) -> dict[int, tuple[int, int, str]]:
    """For each inode in ``inodes``, find a process holding it as a socket FD.

    Returns ``{inode: (pid, fd, comm)}`` for the *first* owner discovered per
    inode (peer ownership is 1-to-1 for connected unix sockets, so a single
    owner is enough). Inodes with no discoverable owner are absent.

    This walks ``/proc/*/fd`` directly, so it only makes sense on a local
    target. Permission errors on individual processes are ignored.
    """
    if not inodes:
        return {}

    result: dict[int, tuple[int, int, str]] = {}
    try:
        proc_entries = os.listdir("/proc")
    except OSError:
        return {}

    for entry in proc_entries:
        if not entry.isdigit():
            continue
        if not inodes - result.keys():
            break
        pid = int(entry)
        fd_dir = f"/proc/{pid}/fd"
        try:
            fd_entries = os.listdir(fd_dir)
        except OSError:
            continue

        comm: str | None = None
        for fd_name in fd_entries:
            try:
                fd = int(fd_name)
            except ValueError:
                continue
            try:
                link = os.readlink(f"{fd_dir}/{fd_name}")
            except OSError:
                continue
            if not link.startswith("socket:["):
                continue
            try:
                inode = int(link[len("socket:[") : -1])
            except ValueError:
                continue
            if inode in inodes and inode not in result:
                if comm is None:
                    try:
                        with open(f"/proc/{pid}/comm") as f:
                            comm = f.read().strip()
                    except OSError:
                        comm = ""
                result[inode] = (pid, fd, comm)

    return result
