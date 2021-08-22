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


def compile_binary(binary_source, binary_out):
    assert os.path.isfile(binary_source)

    subprocess.check_call(['gcc', binary_source, '-o', binary_out])


HELLO = [
    'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.',
    'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)'
]

BINARY_SOURCE = tests.binaries.div_zero_binary.get('binary.c')
BINARY = tests.binaries.div_zero_binary.get('binary')
CORE = tests.binaries.div_zero_binary.get('core')

launched_locally = not (os.environ.get('PWNDBG_TRAVIS_TEST_RUN'))


def test_loads_pure_gdb_without_crashing():
    output = run_gdb_with_script().splitlines()
    assert output == HELLO


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    output = run_gdb_with_script(binary=BINARY).splitlines()

    expected = ['Reading symbols from %s...' % BINARY,
                '(No debugging symbols found in %s)' % BINARY]
    expected += HELLO

    assert all(item in output for item in expected)


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_binary_with_core_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    if not os.path.isfile(CORE):
        create_coredump = ['run', f'generate-core-file {CORE}']
        run_gdb_with_script(binary=BINARY, pyafter=create_coredump)
        assert os.path.isfile(CORE)
    output = run_gdb_with_script(binary=BINARY, core=CORE).splitlines()

    expected = [
        'Reading symbols from %s...' % BINARY,
        '(No debugging symbols found in %s)' % BINARY,
        'Program terminated with signal SIGFPE, Arithmetic exception.',
    ]
    expected += HELLO

    assert all(item in output for item in expected)

    lwp_line = re.compile('^\[New LWP \d+\]$')
    assert any([lwp_line.match(line) for line in output])

    binary_line = re.compile("^Core was generated by .+$")
    assert any([binary_line.match(line) for line in output])

    crash_address_line = re.compile('^#0  0x[0-9a-fA-F]+ in main \(\)$')
    assert any([crash_address_line.match(line) for line in output])


@pytest.mark.skipif(launched_locally, reason='This test uses binaries compiled on travis builds.')
def test_loads_core_without_crashing():
    if not os.path.isfile(BINARY):
        compile_binary(BINARY_SOURCE, BINARY)
    if not os.path.isfile(CORE):
        create_coredump = ['run', f'generate-core-file {CORE}']
        run_gdb_with_script(binary=BINARY, pyafter=create_coredump)
        assert os.path.isfile(CORE)
    output = run_gdb_with_script(core=CORE).splitlines()

    expected = [
        'Program terminated with signal SIGFPE, Arithmetic exception.',
    ]
    expected += HELLO

    assert all(item in output for item in expected)

    lwp_line = re.compile('^\[New LWP \d+\]$')
    assert any([lwp_line.match(line) for line in output])

    binary_line = re.compile("^Core was generated by .+$")
    assert any([binary_line.match(line) for line in output])

    crash_address_line = re.compile('^#0  0x[0-9a-fA-F]+ in \?\? \(\)$')
    assert any([crash_address_line.match(line) for line in output])


def test_entry_no_file_loaded():
    # This test is just to demonstrate that if gdb fails, all we have left is its stdout/err
    output = run_gdb_with_script(binary='not_existing_binary', pyafter='entry').splitlines()

    expected = ['not_existing_binary: No such file or directory.']
    expected += HELLO
    expected += ['entry: There is no file loaded.']

    assert all(item in output for item in expected)
