from __future__ import print_function
from __future__ import unicode_literals

import errno as _errno
import struct

import gdb
import pwndbg as _pwndbg
import pwndbg.arch as _arch
import pwndbg.commands
import pwndbg.regs
import pwndbg.symbol

_errno.errorcode[0] = 'OK'

@_pwndbg.commands.ParsedCommand
def errno(err=None):
    '''Converts errno (or argument) to its string representation'''
    if err is None:
        # Dont ask.
        errno_location = pwndbg.symbol.get('__errno_location')
        err = pwndbg.memory.int(errno_location)
        # err = int(gdb.parse_and_eval('*((int *(*) (void)) __errno_location) ()'))

    err = abs(int(err))

    if err >> 63:
        err -= (1<<64)
    elif err >> 31:
        err -= (1<<32)

    msg = _errno.errorcode.get(int(err), "Unknown error code")
    print("Errno %i: %s" % (err, msg))

@_pwndbg.commands.Command
def pwndbg(filter_pattern=None):
    """
    Prints out a list of all pwndbg commands. The list can be optionally filtered if filter_pattern is passed.
    """
    sorted_commands = list(_pwndbg.commands._Command.commands)
    sorted_commands.sort(key=lambda x: x.__name__)

    if filter_pattern:
        filter_pattern = filter_pattern.lower()

    for c in sorted_commands:
        name = c.__name__
        docs = c.__doc__

        if docs: docs = docs.strip()
        if docs: docs = docs.splitlines()[0]

        if not filter_pattern or filter_pattern in name.lower() or (docs and filter_pattern in docs.lower()):
            print("%-20s %s" % (name, docs))

@_pwndbg.commands.ParsedCommand
def distance(a, b):
    '''Print the distance between the two arguments'''
    a = int(a) & _arch.ptrmask
    b = int(b) & _arch.ptrmask

    distance = (b-a)

    print("%#x->%#x is %#x bytes (%#x words)" % (a, b, distance, distance / _arch.ptrsize))
