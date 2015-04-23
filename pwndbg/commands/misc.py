import errno as _errno
import struct
import pwndbg as _pwndbg

import pwndbg.commands
import pwndbg.regs

_errno.errorcode[0] = 'OK'

@_pwndbg.commands.ParsedCommand
def errno(err=None):
    if err is None:
        err = _pwndbg.regs.retval
        err = _pwndbg.regs[err]

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
