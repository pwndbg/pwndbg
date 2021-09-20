#!/usr/bin/env python
# -*- coding: utf-8 -*-

import codecs
import os
import re
import subprocess

import gdb
import pytest

import tests

from .utils import run_gdb_with_script


@pytest.fixture
def launched_bash_binary():
    path = '/tmp/pwndbg_test_bash'
    subprocess.check_output(['cp', '/bin/bash', path])

    process = subprocess.Popen([path], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    yield process.pid, path

    process.kill()

    os.remove(path)  # Cleanup


def test_attachp_command_attaches_to_procname(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    binary_name = binary_path.split('/')[-1]
    result = run_gdb_with_script(pyafter='attachp %s' % binary_name)

    matches = re.search(r'Attaching to ([0-9]+)', result).groups()
    assert matches == (str(pid),)

    assert re.search(r'Detaching from program: %s, process %s' % (binary_path, pid), result)

def test_attachp_command_attaches_to_pid(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    result = run_gdb_with_script(pyafter='attachp %s' % pid)

    matches = re.search(r'Attaching to ([0-9]+)', result).groups()
    assert matches == (str(pid),)

    assert re.search(r'Detaching from program: %s, process %s' % (binary_path, pid), result)

def test_attachp_command_attaches_to_procname_too_many_pids(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen([binary_path], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    binary_name = binary_path.split('/')[-1]
    result = run_gdb_with_script(pyafter='attachp %s' % binary_name)

    process.kill()

    matches = re.search(r'Found pids: ([0-9]+), ([0-9]+) \(use `attach <pid>`\)', result).groups()
    matches = list(map(int, matches))
    matches.sort()
    
    expected_pids = [pid, process.pid]
    expected_pids.sort()

    assert matches == expected_pids

def test_attachp_command_nonexistent_procname():
    result = run_gdb_with_script(pyafter='attachp some-nonexistent-process-name')  # No chance there is a process name like this
    assert 'Process some-nonexistent-process-name not found' in result

def test_attachp_command_no_pids():
    result = run_gdb_with_script(pyafter='attachp 99999999')  # No chance there is a PID like this
    assert 'Error: ptrace: No such process.' in result

