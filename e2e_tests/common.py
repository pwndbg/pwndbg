#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

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
    assert hello in output, "missing hello msg; output: %r" % output

    output = output[output.index(hello)+len(hello):]

    return output


def pywrite(data):
    return write(data, suffix='.py')


def write(data, suffix=''):
    t = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    t.write(data.encode('utf-8'))
    return t
