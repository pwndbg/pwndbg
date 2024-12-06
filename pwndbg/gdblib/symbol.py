"""
Looking up addresses for function names / symbols, and
vice-versa.

Uses IDA when available if there isn't sufficient symbol
information available.
"""

from __future__ import annotations

import gdb

import pwndbg.lib.cache


@pwndbg.lib.cache.cache_until("stop", "start")
def selected_frame_source_absolute_filename():
    """
    Retrieve the symbol table’s source absolute file name from the selected frame.

    In case of missing symbol table or frame information, None is returned.
    """
    try:
        frame = gdb.selected_frame()
    except gdb.error:
        return None

    if not frame:
        return None

    sal = frame.find_sal()
    if not sal:
        return None

    symtab = sal.symtab
    if not symtab:
        return None

    return symtab.fullname()
