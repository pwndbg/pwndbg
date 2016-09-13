#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

from . import common


def test_loads_wivout_crashing_bruv():
    output = common.run_gdb_with_script()
    assert 'Type pwndbg [filter] for a list.' in output, output
