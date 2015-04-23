"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""
import gdb
import io
import sys
import pwndbg.compat

debug = True

def get(fd, mode):
    file = io.open(1, mode=mode, buffering=0, closefd=False)

    kw = {}
    if pwndbg.compat.python3:
        kw['write_through']=True

    return io.TextIOWrapper(file, **kw)

if debug:
    sys.stdin  = get(0, 'rb')
    sys.stdout = get(1, 'wb')
    sys.stderr = get(2, 'wb')
