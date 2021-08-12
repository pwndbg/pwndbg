#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Provides functionality to circumvent GDB's hooks on sys.stdin and sys.stdout
which prevent output from appearing on-screen inside of certain event handlers.
"""

import sys


class Stdio:
    queue = []

    def __enter__(self, *a, **kw):
        self.queue.append((sys.stdin, sys.stdout, sys.stderr))

        sys.stdin  = sys.__stdin__
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__

    def __exit__(self, *a, **kw):
        sys.stdin, sys.stdout, sys.stderr = self.queue.pop()

stdio = Stdio()
