"""
Functionality for resolving ASCII printable strings within
the debuggee's address space.
"""

from __future__ import annotations

import string

import pwndbg
import pwndbg.aglib.memory

length = 15


def update_length() -> None:
    r"""
    Unfortunately there's not a better way to get at this info.

    >>> gdb.execute('show print elements', from_tty=False, to_string=True)
    'Limit on string chars or array elements to print is 21.\n'
    """
    global length
    length = pwndbg.dbg.string_limit()


def get(address: int, maxlen: int | None = None, maxread: int | None = None) -> str | None:
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
        bytesz = pwndbg.aglib.memory.string(address, maxread)
    except pwndbg.dbg_mod.Error:  # should not happen, but sanity check?
        return None

    sz = bytesz.decode("latin-1", "replace")

    if not sz or not all(s in string.printable for s in sz):
        return None

    if len(sz) < maxlen or not maxlen:
        return sz

    return sz[:maxlen] + "..."
