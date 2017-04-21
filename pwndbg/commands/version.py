#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Displays gdb, python and pwndbg versions.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.color


def _gdb_version():
    return gdb.execute('show version', to_string=True).split('\n')[0]


def _py_version():
    return sys.version.replace('\n', ' ')


@pwndbg.commands.Command
def version():
    """
    Displays gdb, python and pwndbg versions.
    """
    gdb_str = 'Gdb: %s' % _gdb_version()
    py_str = 'Python: %s' % _py_version()
    pwndbg_str = 'Pwndbg: %s' % pwndbg.__version__

    print('\n'.join(map(pwndbg.color.light_red, (gdb_str, py_str, pwndbg_str))))
