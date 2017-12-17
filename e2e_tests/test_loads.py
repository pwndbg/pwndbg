#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from . import common


def test_loads_without_crashing():
    output = common.run_gdb_with_script()

    assert output.endswith(
        'pwndbg: loaded 113 commands. Type pwndbg [filter] for a list.\n'
        'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)\n'
    ), output
