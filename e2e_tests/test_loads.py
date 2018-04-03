#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from . import common

import re


def test_loads_without_crashing():
    output = common.run_gdb_with_script()

    output = re.sub(r'loaded [0-9]+ commands', r'loaded ### commands', output)

    assert (
        'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.\n'
        'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)\n'
    ) in output, "The output was: %r" % output
