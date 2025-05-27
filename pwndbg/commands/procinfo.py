from __future__ import annotations

import shlex
import string

import pwndbg.aglib.file
import pwndbg.aglib.proc
import pwndbg.aglib.qemu
import pwndbg.auxv
import pwndbg.commands
import pwndbg.lib.cache
import pwndbg.lib.net
from pwndbg.color import message
from pwndbg.commands import CommandCategory

"""
PEDA prints it out like this:

exe = /bin/bash
fd[0] -> /dev/pts/96
fd[1] -> /dev/pts/96
fd[2] -> /dev/pts/96
pid = 31102
ppid = 31096
uid = [287138, 287138, 287138, 287138]
gid = [5000, 5000, 5000, 5000]
"""

capabilities = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
}


def tcp(tid: int):
    # For reference, see:
    # https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt
    """
    It will first list all listening TCP sockets, and next list all established
    TCP connections. A typical entry of /proc/net/tcp would look like this (split
    up into 3 parts because of the length of the line):
    """
    data = pwndbg.aglib.file.get(f"/proc/{tid}/net/tcp").decode()
    return pwndbg.lib.net.tcp(data)


def tcp6(tid: int):
    data = pwndbg.aglib.file.get(f"/proc/{tid}/net/tcp6").decode()
    return pwndbg.lib.net.tcp6(data)


def unix(tid: int):
    # We use errors=ignore because of https://github.com/pwndbg/pwndbg/issues/1544
    # TODO/FIXME: this may not be the best solution because we may end up with
    # invalid UDS data. Can this be a problem?
    data = pwndbg.aglib.file.get(f"/proc/{tid}/net/unix").decode(errors="ignore")
    return pwndbg.lib.net.unix(data)


def netlink(tid: int):
    data = pwndbg.aglib.file.get(f"/proc/{tid}/net/netlink").decode()
    return pwndbg.lib.net.netlink(data)


class Process:
    def __init__(self, pid=None, tid=None) -> None:
        if pid is None:
            pid = pwndbg.aglib.proc.pid
        if tid is None:
            tid = pwndbg.aglib.proc.tid
        if not tid:
            tid = pid
        self.pid = pid
        self.tid = tid

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def selinux(self) -> str:
        path = "/proc/%i/task/%i/attr/current" % (self.pid, self.tid)
        try:
            raw = pwndbg.aglib.file.get(path)
            return raw.decode().rstrip("\x00").strip()
        except OSError:
            # This file sometimes cannot be read. This indicates SELinux is not enabled
            return ""

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def cmdline(self):
        raw = pwndbg.aglib.file.get(f"/proc/{self.pid}/cmdline")
        return " ".join(map(shlex.quote, raw.decode().split("\x00")))

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def cwd(self) -> str:
        link = pwndbg.aglib.file.readlink(f"/proc/{self.pid}/cwd")
        return f"'{link}'"

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def status(self):
        raw = pwndbg.aglib.file.get("/proc/%i/task/%i/status" % (self.pid, self.tid))

        status = {}
        for line in raw.splitlines():
            if not line:
                continue

            k_v = line.split(maxsplit=1)

            if len(k_v) == 1:
                k_v.append(b"")

            k, v = k_v

            k = k.decode("latin-1")
            v = v.decode("latin-1")

            k = k.lower().rstrip(":")

            # bit fields
            if set(v) < set(string.hexdigits) and len(v) == 16:
                try:
                    v = int(v, 16)
                except AttributeError:
                    pass

            # vm stats
            elif v.endswith(" kB"):
                v = int(v.split()[0]) * (1 << 10)
            elif v.endswith(" mB"):
                v = int(v.split()[0]) * (1 << 20)

            # misc integers like pid and ppid
            elif str(v).isdigit():
                v = int(v)

            # uid and gid and groups
            elif all(s.isdigit() for s in v.split()):
                v = list(map(int, v.split()))

            # capability sets
            if k in ["capeff", "capinh", "capprm", "capbnd"]:
                orig: int = v
                v = []
                for i in range(max(capabilities) + 1):
                    if (orig >> i) & 1 == 1:
                        v.append(capabilities[i])

            status[k] = v
            setattr(self, k, v)
        return status

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def open_files(self):
        fds = {}

        for i in range(self.fdsize):
            link = pwndbg.aglib.file.readlink("/proc/%i/fd/%i" % (pwndbg.aglib.proc.pid, i))

            if link:
                fds[i] = link

        return fds

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def connections(self):
        # Connections look something like this:
        # socket:[102422]
        fds = self.open_files
        socket = "socket:["
        result = []

        functions = [tcp, tcp6, unix, netlink]

        for fd, path in fds.items():
            if socket not in path:
                continue

            inode = path[len(socket) : -1]
            inode = int(inode)

            for func in functions:
                for x in func(self.tid):
                    if x.inode == inode:
                        x.fd = fd
                        result.append(x)

        return tuple(result)


@pwndbg.commands.Command("Gets the pid.", aliases=["getpid"], category=CommandCategory.PROCESS)
@pwndbg.commands.OnlyWhenRunning
def pid() -> None:
    print(pwndbg.aglib.proc.pid)


@pwndbg.commands.Command(
    "Display information about the running process.", category=CommandCategory.PROCESS
)
@pwndbg.commands.OnlyWhenRunning
def procinfo() -> None:
    """
    Display information about the running process.
    """
    if pwndbg.aglib.qemu.is_qemu():
        print(
            message.error(
                "QEMU target detected: showing result for the qemu process"
                " - so it will be a bit inaccurate (excessive for the parts"
                " used directly by the qemu process)"
            )
        )
    exe = pwndbg.auxv.get().AT_EXECFN
    print("%-10s %r" % ("exe", exe))

    proc = Process()

    # qemu-usermode fail!
    if not proc.status:
        return

    print("%-10s %s" % ("cmdline", proc.cmdline))

    print("%-10s %s" % ("cwd", proc.cwd))

    files = dict(proc.open_files)

    for c in proc.connections:
        files[c.fd] = str(c)

    print("%-10s %s" % ("pid", proc.pid))
    print("%-10s %s" % ("tid", proc.tid))

    # Indicate if the process is restricted by SELinux policies
    if proc.selinux != "" and proc.selinux != "unconfined":
        print("%-10s %s" % ("selinux", proc.selinux))

    print("%-10s %s" % ("ppid", proc.ppid))

    print("%-10s %s" % ("uid", proc.uid))
    print("%-10s %s" % ("gid", proc.gid))
    print("%-10s %s" % ("groups", proc.groups))

    for fd, path in files.items():
        if not set(path) < set(string.printable):
            path = repr(path)

        print("%-10s %s" % ("fd[%i]" % fd, path))

    return
