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
from pwndbg.color import message


def _gdb_version():
    return gdb.execute('show version', to_string=True).split('\n')[0]


def _py_version():
    return sys.version.replace('\n', ' ')


def capstone_version():
    try:
        import capstone
        return '.'.join(map(str, capstone.cs_version()))
    except ImportError:
        return 'not found'


def unicorn_version():
    try:
        import unicorn
        return unicorn.__version__
    except ImportError:
        return 'not found'


@pwndbg.commands.Command
def version():
    """
    Displays gdb, python and pwndbg versions.
    """
    gdb_str      = 'Gdb:      %s' % _gdb_version()
    py_str       = 'Python:   %s' % _py_version()
    pwndbg_str   = 'Pwndbg:   %s' % pwndbg.__version__

    capstone_str = 'Capstone: %s' % capstone_version()
    unicorn_str  = 'Unicorn:  %s' % unicorn_version()

    print('\n'.join(map(message.system, (gdb_str, py_str, pwndbg_str, capstone_str, unicorn_str))))
