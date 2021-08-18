#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import os
import re
import subprocess

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


HELLO = [
    'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.',
    'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)'
]

BASH_BIN = tests.binaries.old_bash.get('binary')
BASH_CORE = tests.binaries.old_bash.get('core')

launched_locally = not (os.environ.get('PWNDBG_TRAVIS_TEST_RUN'))


def test_loads_pure_gdb_without_crashing():
    output = run_gdb_with_script().splitlines()
    assert output == HELLO


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN).splitlines()

    expected = ['Reading symbols from %s...' % BASH_BIN,
                '(No debugging symbols found in %s)' % BASH_BIN]
    expected += HELLO

    assert all(item in output for item in expected)


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_with_core_without_crashing():
    output = run_gdb_with_script(binary=BASH_BIN, core=BASH_CORE).splitlines()

    expected = [
        'Reading symbols from %s...' % BASH_BIN,
        '(No debugging symbols found in %s)' % BASH_BIN,
        '',
        "warning: Can't open file /home/user/pwndbg/tests/corefiles/bash/binary "
        'during file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libnss_files-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libnss_nis-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libnsl-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libnss_compat-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libc-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/libdl-2.19.so during "
        'file-backed mapping note processing', '',
        "warning: Can't open file /lib/x86_64-linux-gnu/ld-2.19.so during file-backed "
        'mapping note processing',
        "[New LWP 13562]", '',
        "warning: Unexpected size of section `.reg-xstate/13562' in core file.", '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libtinfo.so.5" is not '
        'at the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libdl.so.2" is not at '
        'the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libc.so.6" is not at '
        'the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib64/ld-linux-x86-64.so.2" is not at the '
        'expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libnss_compat.so.2" is '
        'not at the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libnsl.so.1" is not at '
        'the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libnss_nis.so.2" is not '
        'at the expected address (wrong library or version mismatch?)', '',
        'warning: .dynamic section for "/lib/x86_64-linux-gnu/libnss_files.so.2" is '
        'not at the expected address (wrong library or version mismatch?)',
        "Core was generated by `/home/user/pwndbg/tests/corefiles/bash/binary'.",
        'Program terminated with signal SIGINT, Interrupt.', '',
        "warning: Unexpected size of section `.reg-xstate/13562' in core file.",
        '#0  0x00007ffff76d36b0 in ?? ()',
    ]
    expected += HELLO

    assert all(item in output for item in expected)


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_core_without_crashing():
    output = run_gdb_with_script(core=BASH_CORE).splitlines()

    expected = [
        '''[New LWP 13562]''',
        '''Core was generated by `/home/user/pwndbg/tests/corefiles/bash/binary'.''',
        '''Program terminated with signal SIGINT, Interrupt.''',
        '''#0  0x00007ffff76d36b0 in ?? ()'''
    ]
    expected += HELLO

    assert all(item in output for item in expected)


def test_entry_no_file_loaded():
    # This test is just to demonstrate that if gdb fails, all we have left is its stdout/err
    output = run_gdb_with_script(binary='not_existing_binary', pyafter='entry').splitlines()

    expected = ['not_existing_binary: No such file or directory.']
    expected += HELLO
    expected += ['entry: There is no file loaded.']

    assert all(item in output for item in expected)
