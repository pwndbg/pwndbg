#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import codecs
import subprocess
import tempfile

import re


def run_gdb_with_script(pybefore='', pyafter=''):
    """
    Runs GDB with given commands (scripts) launched before and after loading of gdbinit.py
    Returns GDB output without ANSI escape codes.
    """
    command = ['gdb', '--silent', '--nx', '--nh']

    if pybefore:
        command += ['--command', pywrite(pybefore).name]

    command += ['--command', 'gdbinit.py']

    if pyafter:
        command += ['--command', pywrite(pyafter).name]

    command += ['--eval-command', 'quit']

    output = subprocess.check_output(command, stderr=subprocess.STDOUT)

    # Python 3 returns bytes-like object so lets have it consistent
    output = codecs.decode(output, 'utf8')

    return escape_ansi(output)


def pywrite(data):
    return write(data, suffix='.py')


def write(data, suffix=''):
    t = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    t.write(data.encode('utf-8'))
    return t


ANSI_ESCAPE = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')


def escape_ansi(line):
    """
    Removes ANSI escape codes.
    Via https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
    """
    return ANSI_ESCAPE.sub('', line)
