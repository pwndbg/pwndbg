"""
Re-implements some psutil functionality to be able to get information from
remote debugging sessions.
"""

from __future__ import annotations

import binascii
import socket
import struct

# http://students.mimuw.edu.pl/lxr/source/include/net/tcp_states.h
TCP_STATUSES = {
    "01": "established",
    "02": "syn_sent",
    "03": "syn_recv",
    "04": "fin_wait1",
    "05": "fin_wait2",
    "06": "time_wait",
    "07": "close",
    "08": "close_wait",
    "09": "last_ack",
    "0A": "listen",
    "0B": "closing",
}


def format_host_port(ip, port):
    if ":" in ip and not ip.startswith("["):
        return f"[{ip}]:{port}"
    return f"{ip}:{port}"


class inode:
    inode: int | None = None


class Connection(inode):
    rhost: str | None = None
    lhost: str | None = None

    rport: int | None = None
    lport: int | None = None

    inode: int | None = None
    status: str | None = None

    family: str | None = None

    def __str__(self) -> str:
        return f"{self.family} {format_host_port(self.lhost, self.lport)} => {format_host_port(self.rhost, self.rport)} ({self.status})"

    def __repr__(self) -> str:
        return f'Connection("{self}")'


class UnixSocket(inode):
    path = "(anonymous)"
    peer_inode: int | None = None
    peer_pid: int | None = None
    peer_fd: int | None = None
    peer_comm: str | None = None

    def __str__(self) -> str:
        s = f"unix {self.path!r}"
        parts: list[str] = []
        if self.inode is not None:
            parts.append(f"inode={self.inode}")
        if self.peer_pid is not None:
            owner = f"pid={self.peer_pid}"
            if self.peer_comm:
                owner += f" '{self.peer_comm}'"
            if self.peer_fd is not None:
                owner += f" fd={self.peer_fd}"
            parts.append(f"peer {owner}")
        elif self.peer_inode:
            parts.append(f"peer_inode={self.peer_inode}")
        if parts:
            s += " (" + ", ".join(parts) + ")"
        return s

    def __repr__(self) -> str:
        return f"UnixSocket({self})"


def _tcp_parser(data: str, ip_family: socket.AddressFamily, endianness: str) -> list[Connection]:
    # For reference, see:
    # https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
    """
    It will first list all listening TCP sockets, and next list all established
    TCP connections. A typical entry of /proc/net/tcp would look like this (split
    up into 3 parts because of the length of the line):
    """
    if not data:
        return []

    result: list[Connection] = []
    for line in data.splitlines()[1:]:
        fields = line.split()
        """
           46: 010310AC:9C4C 030310AC:1770 01
           |      |      |      |      |   |--> connection state
           |      |      |      |      |------> remote TCP port number
           |      |      |      |-------------> remote IPv4 address
           |      |      |--------------------> local TCP port number
           |      |---------------------------> local IPv4 address
           |----------------------------------> number of entry
        """
        local = fields[1]
        remote = fields[2]
        status = fields[3]
        """
           00000150:00000000 01:00000019 00000000
              |        |     |     |       |--> number of unrecovered RTO timeouts
              |        |     |     |----------> number of jiffies until timer expires
              |        |     |----------------> timer_active (see below)
              |        |----------------------> receive-queue
              |-------------------------------> transmit-queue
        """
        """
           1000        0 54165785 4 cd1e6040 25 4 27 3 -1
            |          |    |     |    |     |  | |  | |--> slow start size threshold,
            |          |    |     |    |     |  | |  |      or -1 if the threshold
            |          |    |     |    |     |  | |  |      is >= 0xFFFF
            |          |    |     |    |     |  | |  |----> sending congestion window
            |          |    |     |    |     |  | |-------> (ack.quick<<1)|ack.pingpong
            |          |    |     |    |     |  |---------> Predicted tick of soft clock
            |          |    |     |    |     |              (delayed ACK control data)
            |          |    |     |    |     |------------> retransmit timeout
            |          |    |     |    |------------------> location of socket in memory
            |          |    |     |-----------------------> socket reference count
            |          |    |-----------------------------> inode
            |          |----------------------------------> unanswered 0-window probes
            |---------------------------------------------> uid
        """
        inode = fields[9]

        # Actually extract the useful data
        def split_hist_port(hostport: str):
            host, port = hostport.split(":")
            host = binascii.unhexlify(host)

            if endianness == "little":
                if ip_family == socket.AF_INET:
                    words = struct.unpack("<1I", host)
                    host = struct.pack(">1I", *words)
                elif ip_family == socket.AF_INET6:
                    # The kernel outputs the IPv6 address as 4 little-endian 32-bit chunks.
                    # This behavior is specific to little-endian kernels, such as x86.
                    # On a big-endian kernel, the byte order would differ.
                    # Reference: https://github.com/torvalds/linux/blob/a7c428ee8f59f171a3b57474f2bd5cee0ef1e036/net/ipv6/tcp_ipv6.c#L2153
                    words = struct.unpack("<4I", host)
                    host = struct.pack(">4I", *words)

            host = socket.inet_ntop(ip_family, host)
            port = int(port, 16)
            return host, port

        c = Connection()
        c.rhost, c.rport = split_hist_port(remote)
        c.lhost, c.lport = split_hist_port(local)
        c.inode = int(inode)
        c.status = TCP_STATUSES.get(status, "unknown")
        c.family = "tcp"

        result.append(c)

    return result


def tcp(data: str, endianness: str) -> list[Connection]:
    return _tcp_parser(data, socket.AF_INET, endianness)


def tcp6(data: str, endianness: str) -> list[Connection]:
    return _tcp_parser(data, socket.AF_INET6, endianness)


def unix(data: str) -> list[UnixSocket]:
    if not data:
        return []

    result: list[UnixSocket] = []
    # Note: it is super important to split by "\n" instead of .splitlines() here
    # because there may be a line like this:
    # "0000000000000000: 00000002 00000000 00000000 0002 01 23302 @@@@\x9e\x05@@\x01=\r@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n"
    # and splitlines will also split by \r which we do not want here
    # We also finish at -1 index since with .split() the empty last line is kept in the result
    for line in data.split("\n")[1:-1]:
        """
        Num       RefCount Protocol Flags    Type St Inode Path
        0000000000000000: 00000002 00000000 00010000 0005 01  1536 /dev/socket/msm_irqbalance
        """
        fields = line.split(maxsplit=7)

        u = UnixSocket()
        if len(fields) >= 8:
            u.path = fields[7]
        u.inode = int(fields[6])
        result.append(u)

    return result


NETLINK_TYPES = {
    0: "NETLINK_ROUTE",  # Routing/device hook
    1: "NETLINK_UNUSED",  # Unused number
    2: "NETLINK_USERSOCK",  # Reserved for user mode socket protocols
    3: "NETLINK_FIREWALL",  # Unused number", formerly ip_queue
    4: "NETLINK_SOCK_DIAG",  # socket monitoring
    5: "NETLINK_NFLOG",  # netfilter/iptables ULOG
    6: "NETLINK_XFRM",  # ipsec
    7: "NETLINK_SELINUX",  # SELinux event notifications
    8: "NETLINK_ISCSI",  # Open-iSCSI
    9: "NETLINK_AUDIT",  # auditing
    10: "NETLINK_FIB_LOOKUP",
    11: "NETLINK_CONNECTOR",
    12: "NETLINK_NETFILTER",  # netfilter subsystem
    13: "NETLINK_IP6_FW",
    14: "NETLINK_DNRTMSG",  # DECnet routing messages
    15: "NETLINK_KOBJECT_UEVENT",  # Kernel messages to userspace
    16: "NETLINK_GENERIC",
    18: "NETLINK_SCSITRANSPORT",  # SCSI Transports
    19: "NETLINK_ECRYPTFS",
    20: "NETLINK_RDMA",
    21: "NETLINK_CRYPTO",  # Crypto layer
    22: "NETLINK_SMC",  # SMC monitoring
}

# Multicast group bit flags for NETLINK_ROUTE sockets, matching the legacy
# RTMGRP_* macros from <linux/rtnetlink.h>. Only NETLINK_ROUTE has a stable
# kernel-defined mapping for these bits; other netlink families assign meaning
# to groups in a protocol-specific way, so we don't try to decode them.
RTMGRP_NAMES = {
    0x1: "RTMGRP_LINK",
    0x2: "RTMGRP_NOTIFY",
    0x4: "RTMGRP_NEIGH",
    0x8: "RTMGRP_TC",
    0x10: "RTMGRP_IPV4_IFADDR",
    0x20: "RTMGRP_IPV4_MROUTE",
    0x40: "RTMGRP_IPV4_ROUTE",
    0x80: "RTMGRP_IPV4_RULE",
    0x100: "RTMGRP_IPV6_IFADDR",
    0x200: "RTMGRP_IPV6_MROUTE",
    0x400: "RTMGRP_IPV6_ROUTE",
    0x800: "RTMGRP_IPV6_IFINFO",
    0x1000: "RTMGRP_DECnet_IFADDR",
    0x4000: "RTMGRP_DECnet_ROUTE",
    0x20000: "RTMGRP_IPV6_PREFIX",
}


def _format_netlink_groups(eth: int, groups: int) -> str:
    if groups == 0:
        return "0x0"

    # Only NETLINK_ROUTE has well-known names for individual group bits.
    if eth != 0:
        return hex(groups)

    matched = []
    remaining = groups
    for bit, name in RTMGRP_NAMES.items():
        if groups & bit:
            matched.append(name)
            remaining &= ~bit

    if not matched:
        return hex(groups)

    if remaining:
        matched.append(hex(remaining))

    return "|".join(matched)


class Netlink(inode):
    eth: int = 0
    portid: int | None = None
    groups: int = 0

    def __str__(self) -> str:
        family = NETLINK_TYPES.get(self.eth, f"(unknown netlink {self.eth})")
        groups_str = _format_netlink_groups(self.eth, self.groups)
        return f"socket:{family} (inode={self.inode}, portid={self.portid}, groups={groups_str})"

    def __repr__(self) -> str:
        return f"Netlink({self})"


def netlink(data: str) -> list[Netlink]:
    if not data:
        return []

    result: list[Netlink] = []
    for line in data.splitlines()[1:]:
        # sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode
        fields = line.split()

        n = Netlink()
        n.eth = int(fields[1])
        n.portid = int(fields[2])  # 'Pid' in Netlink context refers to Port ID, not Process ID
        n.groups = int(fields[3], 16)
        n.inode = int(fields[9])
        result.append(n)

    return result
