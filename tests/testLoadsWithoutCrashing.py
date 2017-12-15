#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from .common import run_gdb_with_script, server

def test_loads_wivout_crashing_bruv():
    output = run_gdb_with_script()
    assert 'Type pwndbg [filter] for a list.' in output, output
