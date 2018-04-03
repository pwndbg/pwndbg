#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import codecs
import re
import subprocess
import tempfile


def run_gdb_with_script(binary='', core='', pybefore=None, pyafter=None):
    """
    Runs GDB with given commands launched before and after loading of gdbinit.py
    Returns GDB output.
    """
    pybefore = ([pybefore] if isinstance(pybefore, str) else pybefore) or []
    pyafter = ([pyafter] if isinstance(pyafter, str) else pyafter) or []

    command = ['gdb', '--silent', '--nx', '--nh']
    
    if binary:
        command += [binary]

    if core:
        command += ['--core', core]

    for cmd in pybefore:
        command += ['--eval-command', cmd]

    command += ['--command', 'gdbinit.py']

    for cmd in pyafter:
        command += ['--eval-command', cmd]

    command += ['--eval-command', 'quit']

    print("Launching command: %s" % command)
    output = subprocess.check_output(command, stderr=subprocess.STDOUT)

    # Python 3 returns bytes-like object so lets have it consistent
    output = codecs.decode(output, 'utf8')

    output = re.sub(r'loaded [0-9]+ commands', r'loaded ### commands', output)

    # Strip the hello msg
    hello = (
        'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.\n'
        'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)\n'
    )
    assert hello in output

    output = output[output.index(hello)+len(hello):]

    return output


BASH_BIN = './tests/corefiles/bash/binary'
BASH_CORE = './tests/corefiles/bash/core'


def test_loads_pure_gdb_without_crashing():
    output = run_gdb_with_script()
    assert output == ''

def test_loads_binary_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN)
    assert output == ''


def test_loads_binary_with_core_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN, core=BASH_CORE)
    assert output == ''


def test_loads_core_without_crashing():
    output = run_gdb_with_script(core=BASH_CORE)
    assert output == ''


def test_entry_no_file_loaded():
    # This test is just to demonstrate that if gdb fails, all we have left is its stdout/err
    output = run_gdb_with_script(binary='not_existing_binary', pyafter='entry')
    assert output == 'entry: There is no file loaded.\n'
