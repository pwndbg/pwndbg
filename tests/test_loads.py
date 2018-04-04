#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import os
import re
import subprocess
import tempfile

import pytest

import tests


def run_gdb_with_script(binary='', core='', pybefore=None, pyafter=None):
    """
    Runs GDB with given commands launched before and after loading of gdbinit.py
    Returns GDB output.
    """
    pybefore = ([pybefore] if isinstance(pybefore, str) else pybefore) or []
    pyafter = ([pyafter] if isinstance(pyafter, str) else pyafter) or []

    command = ['gdb', '--silent', '--nx', '--nh']
    
    for cmd in pybefore:
        command += ['--eval-command', cmd]

    command += ['--command', 'gdbinit.py']

    if binary:
        command += [binary]

    if core:
        command += ['--core', core]


    for cmd in pyafter:
        command += ['--eval-command', cmd]

    command += ['--eval-command', 'quit']

    print("Launching command: %s" % command)
    output = subprocess.check_output(command, stderr=subprocess.STDOUT)

    # Python 3 returns bytes-like object so lets have it consistent
    output = codecs.decode(output, 'utf8')

    # The pwndbg banner shows number of loaded commands, it might differ between
    # testing environments, so lets change it to ###
    output = re.sub(r'loaded [0-9]+ commands', r'loaded ### commands', output)

    return output

HELLO = (
    'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.\n'
    'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)\n'
)

BASH_BIN = tests.binaries.old_bash.get('binary')
BASH_CORE = tests.binaries.old_bash.get('core')

launched_locally = not(os.environ.get('PWNDBG_TRAVIS_TEST_RUN'))


def test_loads_pure_gdb_without_crashing():
    output = run_gdb_with_script()
    assert output == HELLO


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN)

    expected = 'Reading symbols from %s...(no debugging symbols found)...done.\n' % BASH_BIN
    expected += HELLO

    assert output == expected


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_with_core_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN, core=BASH_CORE)

    expected = 'Reading symbols from %s...(no debugging symbols found)...done.\n' % BASH_BIN
    expected += HELLO

    # TODO / FIXME: it should fail and should be fixed according to travis output
    assert output == expected


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_core_without_crashing():
    output = run_gdb_with_script(core=BASH_CORE)
    # TODO / FIXME: it should fail and should be fixed according to travis output
    assert output == HELLO


def test_entry_no_file_loaded():
    # This test is just to demonstrate that if gdb fails, all we have left is its stdout/err
    output = run_gdb_with_script(binary='not_existing_binary', pyafter='entry')

    expected = 'not_existing_binary: No such file or directory.\n'
    expected += HELLO
    expected += 'entry: There is no file loaded.\n'

    assert output == expected
