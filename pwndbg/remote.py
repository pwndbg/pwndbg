#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Information about whether the debuggee is local (under GDB) or remote
(under GDBSERVER or QEMU stub).
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb


def is_remote():
    # N.B.: We cannot use "info program" because of:
    # https://sourceware.org/bugzilla/show_bug.cgi?id=18335
    #
    # return 'serial line' in gdb.execute('info program',to_string=True,)

    return 'Remote serial target' in gdb.execute('info file',to_string=True,from_tty=False)
