#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import codecs
import subprocess
import tempfile

import os
import re

import logging


def run_gdb_with_script(binary='', core='', pybefore='', pyafter=''):
    """
    Runs GDB with given commands (scripts) launched before and after loading of gdbinit.py
    Returns GDB output.
    """
    command = ['gdb', '--silent', '--nx', '--nh']

    if binary:
        command += [binary]

    if core:
        command += ['--core', core]

    if pybefore:
        command += ['--command', pywrite(pybefore).name]

    command += ['--command', 'gdbinit.py']

    if pyafter:
        command += ['--command', pywrite(pyafter).name]

    command += ['--eval-command', 'quit']

    logging.info("Launching command: %s", command)
    envs = os.environ.copy()
    envs['PWNDBG_E2E_TESTS_DISABLE_COLORS'] = 'yes'
    output = subprocess.check_output(command, stderr=subprocess.STDOUT, env=envs)

    # Python 3 returns bytes-like object so lets have it consistent
    output = codecs.decode(output, 'utf8')

    output = re.sub(r'loaded [0-9]+ commands', r'loaded ### commands', output)

    # Strip the hello msg
    hello = (
        'pwndbg: loaded ### commands. Type pwndbg [filter] for a list.\n'
        'pwndbg: created $rebase, $ida gdb functions (can be used with print/break)\n'
    )
    assert hello in output, "missing hello msg"

    output = output[output.index(hello)+len(hello):]

    return output


def pywrite(data):
    return write(data, suffix='.py')


def write(data, suffix=''):
    t = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    t.write(data.encode('utf-8'))
    return t

