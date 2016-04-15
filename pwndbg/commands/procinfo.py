import os
import string

import gdb
import pwndbg.auxv
import pwndbg.commands
import pwndbg.memoize
import pwndbg.net
import pwndbg.file
import pwndbg.proc

try:
    import psutil
except:
    psutil = None

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

class Process():
    def __init__(self, pid=None):
        if pid is None:
            pid = pwndbg.proc.pid
        self.pid = pid
        self.status

    @property
    @pwndbg.memoize.reset_on_stop
    def status(self):
        raw = pwndbg.file.get('/proc/%i/status' % self.pid)

        status = {}
        for line in raw.splitlines():
            if not line:
                continue

            k_v = line.split(None, 1)

            if len(k_v) == 1:
                k_v.append(b'')

            k,v = k_v

            # Python3 ftw!
            k = k.decode('latin-1')
            v = v.decode('latin-1')

            k = k.lower().rstrip(':')

            # bit fields
            if set(v) < set(string.hexdigits) and len(v) == 16:
                try:
                    v = int(v, 16)
                except AttributeError:
                    pass

            # vm stats
            elif v.endswith(' kB'):
                v = int(v.split()[0]) * (1<<10)
            elif v.endswith(' mB'):
                v = int(v.split()[0]) * (1<<20)

            # misc integers like pid and ppid
            elif v.isdigit():
                v = int(v)

            # uid and gid and groups
            elif all(map(str.isdigit, v.split())):
                v = list(map(int, v.split()))

            status[k] = v
            setattr(self, k, v)
        return status

    @property
    @pwndbg.memoize.reset_on_stop
    def open_files(self):
        fds = {}

        for i in range(self.fdsize):
            link = pwndbg.file.readlink('/proc/%i/fd/%i' % (pwndbg.proc.pid, i))

            if link:
                fds[i] = link

        return fds

    @property
    @pwndbg.memoize.reset_on_stop
    def connections(self):
        # Connections look something like this: 
        # socket:[102422]
        fds = self.open_files
        socket = 'socket:['
        result = []

        functions = [pwndbg.net.tcp, 
                     pwndbg.net.unix, 
                     pwndbg.net.netlink]

        for fd, path in fds.items():
            if socket not in path:
                continue

            inode = path[len(socket):-1]
            inode = int(inode)

            for func in functions:
                for x in func():
                    if x.inode == inode:
                        x.fd = fd
                        result.append(x)

        return tuple(result)

@pwndbg.commands.Command
def pid():
    print(pwndbg.proc.pid)

@pwndbg.commands.Command
def procinfo():
    """
    Display information about the running process.
    """
    if not psutil:
        print("psutil required but not installed")
        return
    
    exe  = str(pwndbg.auxv.get()['AT_EXECFN'])
    print("%-10s %r" % ("exe", exe))

    proc = Process()

    # qemu-usermode fail!
    if not proc.status:
        return

    pid  = proc.pid
    ppid = proc.ppid
    uids = proc.uid
    gids = proc.gid

    files = dict(proc.open_files)

    for c in proc.connections:
        files[c.fd] = str(c) 

    print("%-10s %s" % ("pid", pid))
    print("%-10s %s" % ("ppid", ppid))
    print("%-10s %s" % ("uid", uids))
    print("%-10s %s" % ("gid", gids))
    for fd, path in files.items():
        if not set(path) < set(string.printable):
            path = repr(path)

        print("%-10s %s" % ("fd[%i]" % fd, path))

    return
