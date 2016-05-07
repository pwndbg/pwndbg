from __future__ import print_function
import gdb
import errno as _errno
import struct
import pwndbg as _pwndbg

import pwndbg.arch as _arch
import pwndbg.commands
import pwndbg.regs


_errno.errorcode[0] = 'OK'

@_pwndbg.commands.ParsedCommand
def errno(err=None):
    '''Converts errno (or argument) to its string representation'''
    if err is None:
        # Dont ask.
        err = int(gdb.parse_and_eval('*((int *(*) (void)) __errno_location) ()'))

    err = abs(int(err))

    if err >> 63:
        err -= (1<<64)
    elif err >> 31:
        err -= (1<<32)

    msg = _errno.errorcode.get(int(err), "Unknown error code")
    print("Errno %i: %s" % (err, msg))

@_pwndbg.commands.Command
def pwndbg():
    """
    Prints out a list of all pwndbg commands.
    """
    sorted_commands = list(_pwndbg.commands._Command.commands)
    sorted_commands.sort(key=lambda x: x.__name__)
    for c in sorted_commands:
        name = c.__name__
        docs = c.__doc__

        if docs: docs = docs.strip()
        if docs: docs = docs.splitlines()[0]

        print("%-20s %s" % (name, docs))

@_pwndbg.commands.ParsedCommand
def distance(a, b):
    '''Print the distance between the two arguments'''
    a = int(a) & _arch.ptrmask
    b = int(b) & _arch.ptrmask

    distance = (b-a)

    print("%#x->%#x is %#x bytes (%#x words)" % (a, b, distance, distance / _arch.ptrsize))
