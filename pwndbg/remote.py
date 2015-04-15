#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""
import gdb


def is_remote():
    return 'serial line' in gdb.execute('info program',to_string=True)
