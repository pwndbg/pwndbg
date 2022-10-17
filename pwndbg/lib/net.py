"""
Re-implements some psutil functionality to be able to get information from
remote debugging sessions.
"""

import binascii
import socket

import pwndbg.gdblib.arch
import pwndbg.gdblib.file

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


class inode:
    inode = None


class Connection(inode):
    rhost = None
    lhost = None

    rport = None
    lport = None

    inode = None
    status = None

    family = None

    def __str__(self):
        return "%s %s:%s => %s:%s (%s)" % (
            self.family,
            self.lhost,
            self.lport,
            self.rhost,
            self.rport,
            self.status,
        )

    def __repr__(self):
        return 'Connection("%s")' % self


class UnixSocket(inode):
    path = "(anonymous)"

    def __str__(self):
        return "unix %r" % self.path

    def __repr__(self):
        return "UnixSocket(%s)" % self


def tcp(data: str):
    # For reference, see:
    # https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
    """
    It will first list all listening TCP sockets, and next list all established
    TCP connections. A typical entry of /proc/net/tcp would look like this (split
    up into 3 parts because of the length of the line):
    """
    if not data:
        return []

    result = []
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
        def split_hist_port(hostport):
            host, port = hostport.split(":")
            host = binascii.unhexlify(host)

            if pwndbg.gdblib.arch.endian == "little":
                host = host[::-1]

            host = socket.inet_ntop(socket.AF_INET, host)
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


def unix(data: str):
    if not data:
        return []

    result = []
    for line in data.splitlines()[1:]:
        """
        Num       RefCount Protocol Flags    Type St Inode Path
        0000000000000000: 00000002 00000000 00010000 0005 01  1536 /dev/socket/msm_irqbalance
        """
        fields = line.split(None, 7)

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
    10: "NETLINK_FIB_LOOKUP",  #
    11: "NETLINK_CONNECTOR",  #
    12: "NETLINK_NETFILTER",  # netfilter subsystem
    13: "NETLINK_IP6_FW",  #
    14: "NETLINK_DNRTMSG",  # DECnet routing messages
    15: "NETLINK_KOBJECT_UEVENT",  # Kernel messages to userspace
    16: "NETLINK_GENERIC",  #
    18: "NETLINK_SCSITRANSPORT",  # SCSI Transports
    19: "NETLINK_ECRYPTFS",  #
    20: "NETLINK_RDMA",  #
    21: "NETLINK_CRYPTO",  # Crypto layer
}


class Netlink(inode):
    eth = 0
    pid = None

    def __str__(self):
        return NETLINK_TYPES.get(self.eth, "(unknown netlink)")

    def __repr__(self):
        return "Netlink(%s)" % self


def netlink(data: str):
    if not data:
        return []

    result = []
    for line in data.splitlines()[1:]:
        # sk       Eth Pid    Groups   Rmem     Wmem     Dump     Locks     Drops     Inode            [10/8747]
        fields = line.split()

        n = Netlink()
        n.eth = int(fields[1])
        n.pid = int(fields[2])
        n.inode = int(fields[9])
        result.append(n)

    return result
