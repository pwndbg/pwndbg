#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import unicode_literals

import re

from . import common


def escape_ansi(line):
    # via https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)


def test_loads_wivout_crashing_bruv():
    output = escape_ansi(common.run_gdb_with_script())

    assert ('pwndbg: loaded 159 commands. Type pwndbg [filter] for a list.\n'
            'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)') in output, output
