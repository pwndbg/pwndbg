"""
Functionality for resolving ASCII printable strings within
the debuggee's address space.
"""

import string

import gdb

import pwndbg.gdblib.events
import pwndbg.gdblib.memory

length = 15


@pwndbg.gdblib.events.stop
def update_length():
    r"""
    Unfortunately there's not a better way to get at this info.

    >>> gdb.execute('show print elements', from_tty=False, to_string=True)
    'Limit on string chars or array elements to print is 21.\n'
    """
    global length
    message = gdb.execute("show print elements", from_tty=False, to_string=True)
    message = message.split("\n")[0].split()[-1]
    message = message.strip(".")
    if message == "unlimited":
        length = 0
    else:
        length = int(message)


def get(address, maxlen=None, maxread=None):
    """
    Returns a printable C-string from address.

    Returns `None` if string contains non-printable chars
    or if the `maxlen` length data does not end up with a null byte.
    """
    if maxlen is None:
        maxlen = length

    if maxread is None:
        maxread = length

    try:
        sz = pwndbg.gdblib.memory.string(address, maxread)
    except gdb.error:  # should not happen, but sanity check?
        return None

    sz = sz.decode("latin-1", "replace")

    if not sz or not all(s in string.printable for s in sz):
        return None

    if len(sz) < maxlen or not maxlen:
        return sz

    return sz[:maxlen] + "..."
