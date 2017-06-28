#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Wrappers to external utilities.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import functools
import subprocess

import pwndbg.which


def call_program(progname, *args):
    program = pwndbg.which.which(progname)

    if not program:
        raise OSError('Could not find %s command in $PATH.' % progname)

    cmd = [progname] + list(args)

    try:
        return subprocess.check_output(cmd).decode('utf-8')
    except Exception as e:
        raise OSError('Error during execution of %s command: %s' % (progname, e))

checksec = functools.partial(call_program,'checksec')
readelf = functools.partial(call_program, 'readelf')
file = functools.partial(call_program, 'file')
