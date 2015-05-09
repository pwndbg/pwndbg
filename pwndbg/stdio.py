"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""
import io
import os
import sys

import gdb
import pwndbg.compat

import gdb
import pwndbg.compat

def get(fd, mode):
    file = io.open(fd, mode=mode, buffering=0, closefd=False)
    return io.TextIOWrapper(file, write_through=True)

class Stdio(object):
    queue = []

    def __enter__(self, *a, **kw):
        self.queue.append((sys.stdin, sys.stdout, sys.stderr))
        if pwndbg.compat.python3:
            sys.stdin  = get(0, 'rb')
            sys.stdout = get(1, 'wb')
            sys.stderr = get(2, 'wb')

    def __exit__(self, *a, **kw):
        sys.stdin, sys.stdout, sys.stderr = self.queue.pop()

stdio = Stdio()

if False:
    sys.stdin  = get(0, 'rb')
    sys.stdout = get(1, 'wb')
    sys.stderr = get(2, 'wb')
