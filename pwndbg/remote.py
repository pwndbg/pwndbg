#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""

import gdb

import pwndbg.memoize


@pwndbg.memoize.reset_on_objfile
def is_remote():
    # Example:
    # pwndbg> maintenance print target-stack
    # The current target stack is:
    #   - remote (Remote serial target in gdb-specific protocol)
    #   - exec (Local exec file)
    #   - None (None)
    return "remote" in gdb.execute("maintenance print target-stack", to_string=True)
