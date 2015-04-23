import pwndbg.commands
import pwndbg.regs
import errno as _errno
import struct

_errno.errorcode[0] = 'OK'

@pwndbg.commands.ParsedCommand
def errno(err=None):
    if err is None:
        err = pwndbg.regs.retval
        err = pwndbg.regs[err]

    err = abs(int(err))

    if err >> 63:
        err -= (1<<64)
    elif err >> 31:
        err -= (1<<32)

    msg = _errno.errorcode.get(int(err), "Unknown error code")
    print "Errno %i: %s" % (err, msg)