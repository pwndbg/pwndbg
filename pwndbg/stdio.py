"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""
import io
import sys

import gdb
import pwndbg.compat

def get(fd, mode):
    file = io.open(1, mode=mode, buffering=0, closefd=False)

    kw = {}
    if pwndbg.compat.python3:
        kw['write_through']=True

    return io.TextIOWrapper(file, **kw)

stdin  = get(0, 'rb')
stdout = get(1, 'wb')
stderr = get(2, 'wb')

class Stdio(object):
    queue = []

    def __enter__(self, *a, **kw):
        self.queue.append((sys.stdin, sys.stdout, sys.stderr))
        sys.stdin  = get(0, 'rb')
        sys.stdout = get(1, 'wb')
        sys.stderr = get(2, 'wb')

    def __exit__(self, *a, **kw):
        sys.stdin, sys.stdout, sys.stderr = self.queue.pop()

stdio = Stdio()
