import os

import gdb
import pwndbg.auxv
import pwndbg.commands
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

@pwndbg.commands.Command
def procinfo():
    """
    Display information about the running process.
    """
    if not psutil:
        print("psutil required but not installed")
        return

    exe  = repr(str(pwndbg.auxv.get()['AT_EXECFN']))

    proc = psutil.Process(pwndbg.proc.pid)

    pid  = proc.pid
    ppid = proc.ppid()

    uids = proc.uids()
    uids = [uids.real, uids.effective, uids.saved]

    gids = proc.gids()
    gids = [gids.real, gids.effective, gids.saved]

    files = {f.fd:repr(str(f.path)) for f in proc.open_files()}

    for c in proc.connections():
        files[c.fd] = '%s:%s => %s:%s' % (c.laddr + c.raddr)

    for fd in os.listdir("/proc/%d/fd" % pid):
        fd = int(fd)
        if fd in files:
            continue
        files[fd] = repr(str(os.path.realpath("/proc/%d/fd/%s" % (pid, fd))))

    print("%-10s %s" % ("exe", exe))
    print("%-10s %s" % ("pid", pid))
    print("%-10s %s" % ("ppid", ppid))
    print("%-10s %s" % ("uid", uids))
    print("%-10s %s" % ("gid", gids))
    for fd, path in files.items():
        print("%-10s %s" % ("fd[%i]" % fd, path))

    return
