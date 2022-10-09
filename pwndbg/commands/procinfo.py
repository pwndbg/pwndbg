import string

import pwndbg.auxv
import pwndbg.commands
import pwndbg.gdblib.file
import pwndbg.gdblib.net
import pwndbg.gdblib.proc
import pwndbg.lib.memoize

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


class Process:
    def __init__(self, pid=None, tid=None):
        if pid is None:
            pid = pwndbg.gdblib.proc.pid
        if tid is None:
            tid = pwndbg.gdblib.proc.tid
        if not tid:
            tid = pid
        self.pid = pid
        self.tid = tid

        # Precalculate
        self.status

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def selinux(self):
        path = "/proc/%i/task/%i/attr/current" % (self.pid, self.tid)
        raw = pwndbg.gdblib.file.get(path)
        return raw.decode().rstrip("\x00").strip()

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def status(self):
        raw = pwndbg.gdblib.file.get("/proc/%i/task/%i/status" % (self.pid, self.tid))

        status = {}
        for line in raw.splitlines():
            if not line:
                continue

            k_v = line.split(None, 1)

            if len(k_v) == 1:
                k_v.append(b"")

            k, v = k_v

            # Python3 ftw!
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
            elif all((s.isdigit() for s in v.split())):
                v = list(map(int, v.split()))

            # capability sets
            if k in ["capeff", "capinh", "capprm", "capbnd"]:
                orig = v
                v = []
                for i in range(max(capabilities) + 1):
                    if (orig >> i) & 1 == 1:
                        v.append(capabilities[i])

            status[k] = v
            setattr(self, k, v)
        return status

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def open_files(self):
        fds = {}

        for i in range(self.fdsize):
            link = pwndbg.gdblib.file.readlink("/proc/%i/fd/%i" % (pwndbg.gdblib.proc.pid, i))

            if link:
                fds[i] = link

        return fds

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def connections(self):
        # Connections look something like this:
        # socket:[102422]
        fds = self.open_files
        socket = "socket:["
        result = []

        functions = [pwndbg.gdblib.net.tcp, pwndbg.gdblib.net.unix, pwndbg.gdblib.net.netlink]

        for fd, path in fds.items():
            if socket not in path:
                continue

            inode = path[len(socket) : -1]
            inode = int(inode)

            for func in functions:
                for x in func():
                    if x.inode == inode:
                        x.fd = fd
                        result.append(x)

        return tuple(result)


@pwndbg.commands.ArgparsedCommand("Gets the pid.")
@pwndbg.commands.OnlyWhenRunning
def pid():
    print(pwndbg.gdblib.proc.pid)


@pwndbg.commands.ArgparsedCommand("Display information about the running process.")
@pwndbg.commands.OnlyWhenRunning
def procinfo():
    """
    Display information about the running process.
    """
    exe = str(pwndbg.auxv.get()["AT_EXECFN"])
    print("%-10s %r" % ("exe", exe))

    proc = Process()

    # qemu-usermode fail!
    if not proc.status:
        return

    files = dict(proc.open_files)

    for c in proc.connections:
        files[c.fd] = str(c)

    print("%-10s %s" % ("pid", proc.pid))
    print("%-10s %s" % ("tid", proc.tid))

    if proc.selinux != "unconfined":
        print("%-10s %s" % ("selinux", proc.selinux))

    print("%-10s %s" % ("ppid", proc.ppid))

    if not pwndbg.gdblib.android.is_android():
        print("%-10s %s" % ("uid", proc.uid))
        print("%-10s %s" % ("gid", proc.gid))
        print("%-10s %s" % ("groups", proc.groups))
    else:
        print("%-10s %s" % ("uid", list(map(pwndbg.lib.android.aid_name, proc.uid))))
        print("%-10s %s" % ("gid", list(map(pwndbg.lib.android.aid_name, proc.gid))))
        print("%-10s %s" % ("groups", list(map(pwndbg.lib.android.aid_name, proc.groups))))

    for fd, path in files.items():
        if not set(path) < set(string.printable):
            path = repr(path)

        print("%-10s %s" % ("fd[%i]" % fd, path))

    return
