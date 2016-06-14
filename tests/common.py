from __future__ import unicode_literals

import subprocess
import tempfile
import unittest


def pywrite(data):
    return write(data, suffix='.py')

def write(data, suffix=''):
    t = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    t.write(data.encode('utf-8'))
    return t

def run_gdb_with_script(pybefore='', pyafter=''):
    command = ['gdb','--silent','--nx','--nh']

    if pybefore:
        command += ['--command', pywrite(pybefore).name]

    command += ['--command', 'gdbinit.py']

    if pyafter:
        command += ['--command', pywrite(pyafter).name]

    command += ['--eval-command', 'quit']

    return subprocess.check_output(command, stderr=subprocess.STDOUT)
