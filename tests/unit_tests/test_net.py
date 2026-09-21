from __future__ import annotations

from pwndbg.lib.net import _format_netlink_groups
from pwndbg.lib.net import netlink
from pwndbg.lib.net import unix

# Sample data based on real /proc/net/netlink output. The header line is
# always present and is skipped by the parser; subsequent lines describe one
# socket each. Reference:
#   sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
NETLINK_SAMPLE = """\
sk               Eth Pid        Groups   Rmem     Wmem     Dump  Locks    Drops    Inode
00000000e4931d0c 0   2362       00000140 0        0        0     2        0        23942
00000000a1b2c3d4 12  4096       00000000 0        0        0     2        0        12345
00000000deadbeef 15  0          ffffffff 0        0        0     2        0        99999
"""


def test_netlink_parses_all_fields() -> None:
    sockets = netlink(NETLINK_SAMPLE)
    assert len(sockets) == 3

    route, nf, uevent = sockets

    assert route.eth == 0
    assert route.portid == 2362
    assert route.groups == 0x140
    assert route.inode == 23942

    assert nf.eth == 12
    assert nf.portid == 4096
    assert nf.groups == 0
    assert nf.inode == 12345

    assert uevent.eth == 15
    assert uevent.portid == 0
    assert uevent.groups == 0xFFFFFFFF
    assert uevent.inode == 99999


def test_netlink_str_route_decodes_named_groups() -> None:
    sockets = netlink(NETLINK_SAMPLE)
    rendered = str(sockets[0])
    # NETLINK_ROUTE has well-known RTMGRP_* names, so groups=0x140 should be
    # decoded as RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR.
    assert "socket:NETLINK_ROUTE" in rendered
    assert "inode=23942" in rendered
    assert "portid=2362" in rendered
    assert "RTMGRP_IPV4_ROUTE" in rendered
    assert "RTMGRP_IPV6_IFADDR" in rendered


def test_netlink_str_non_route_uses_hex_groups() -> None:
    sockets = netlink(NETLINK_SAMPLE)
    nf = sockets[1]
    rendered = str(nf)
    # NETLINK_NETFILTER has no kernel-defined name table for group bits,
    # so we should fall back to a raw hex value.
    assert "socket:NETLINK_NETFILTER" in rendered
    assert "groups=0x0" in rendered

    uevent_rendered = str(sockets[2])
    assert "socket:NETLINK_KOBJECT_UEVENT" in uevent_rendered
    assert "groups=0xffffffff" in uevent_rendered


def test_netlink_empty_input() -> None:
    assert netlink("") == []


def test_format_netlink_groups_zero() -> None:
    assert _format_netlink_groups(0, 0) == "0x0"
    assert _format_netlink_groups(12, 0) == "0x0"


def test_format_netlink_groups_route_known_bits() -> None:
    assert _format_netlink_groups(0, 0x1) == "RTMGRP_LINK"
    assert _format_netlink_groups(0, 0x10 | 0x40) == "RTMGRP_IPV4_IFADDR|RTMGRP_IPV4_ROUTE"


def test_format_netlink_groups_route_with_unknown_bits() -> None:
    # If there are bits we don't recognize, we still decode the known ones
    # and append the residual as hex.
    formatted = _format_netlink_groups(0, 0x1 | 0x80000000)
    assert formatted.startswith("RTMGRP_LINK|")
    assert "0x80000000" in formatted


def test_format_netlink_groups_non_route_is_hex() -> None:
    assert _format_netlink_groups(12, 0x140) == "0x140"
    assert _format_netlink_groups(15, 0x1) == "0x1"


def test_unix_preserves_carriage_return_in_socket_path() -> None:
    data = (
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00000000 0002 01 23302 "
        "@@@@\x9e\x05@@\x01=\r@@@@@@@@\n"
    )

    sockets = unix(data)

    assert len(sockets) == 1
    assert sockets[0].inode == 23302
    assert sockets[0].path == "@@@@\x9e\x05@@\x01=\r@@@@@@@@"


def test_unix_socket_path_with_cr_and_newline() -> None:
    # A socket bound to the literal path "/tmp/sock\r\nwith\nnewlines".
    # The kernel writes the path verbatim to /proc/net/unix, so
    # a single entry spans multiple lines and also contains a "\r" that
    #  must not be split on. The parser should glue the continuation lines
    # back together
    data = (
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00010000 0001 01 12345 "
        "/tmp/sock\r\nwith\nnewlines\n"
        "0000000000000000: 00000003 00000000 00000000 0001 03 67890\n"
    )

    sockets = unix(data)

    assert len(sockets) == 2
    assert sockets[0].inode == 12345
    assert sockets[0].path == "/tmp/sock\r\nwith\nnewlines"
    assert sockets[1].inode == 67890
    assert sockets[1].path == "(anonymous)"


def test_unix_parses_entry_without_path() -> None:
    data = (
        "Num       RefCount Protocol Flags    Type St Inode Path\n"
        "0000000000000000: 00000002 00000000 00000000 0002 01 12345 /tmp/sock\n"
        "0000000000000000: 00000003 00000000 00000000 0001 03 9571\n"
    )

    sockets = unix(data)

    assert len(sockets) == 2
    assert sockets[0].inode == 12345
    assert sockets[0].path == "/tmp/sock"
    assert sockets[1].inode == 9571
    assert sockets[1].path == "(anonymous)"


def test_unix_empty_input() -> None:
    assert unix("") == []
