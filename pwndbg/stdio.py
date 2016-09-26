#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import io
import os
import sys

import gdb

import pwndbg.compat


def get(fd, mode):
    if pwndbg.compat.python3:
        file = io.open(fd, mode=mode, buffering=0)

        kw ={}
        if pwndbg.compat.python3:
            kw['write_through']=True

        return io.TextIOWrapper(file, **kw)
    else:
        return codecs.open(fd, mode, 'utf-8')


class Stdio(object):
    queue = []

    def __enter__(self, *a, **kw):
        self.queue.append((sys.stdin, sys.stdout, sys.stderr))

        if pwndbg.compat.python3 or True:
            sys.stdin  = get('/dev/stdin', 'rb')
            sys.stdout = get('/dev/stdout', 'wb')
            sys.stderr = get('/dev/stderr', 'wb')

    def __exit__(self, *a, **kw):
        sys.stdin, sys.stdout, sys.stderr = self.queue.pop()

stdio = Stdio()

if False:
    sys.stdin  = get(0, 'rb')
    sys.stdout = get(1, 'wb')
    sys.stderr = get(2, 'wb')
