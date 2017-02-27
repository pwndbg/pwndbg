#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import atexit
import functools
import subprocess
import sys
import tempfile
import time
import unittest

from . import xmlhacks

def pywrite(data):
    return write(data, suffix='.py')

def write(data, suffix=''):
    t = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
    t.write(data.encode('utf-8'))
    return t

def gdb_with_script(pybefore='', pyafter=''):
    command = ['gdb','--silent','--nx','--nh']

    if pybefore:
        command += ['--command', pywrite(pybefore).name]

    command += ['--command', 'gdbinit.py']

    if pyafter:
        command += ['--command', pywrite(pyafter).name]

    command += ['--eval-command', 'quit']
    return command

def run_gdb_with_script(*a, **kw):
    command = gdb_with_script(*a, **kw)
    return subprocess.check_output(command, stderr=subprocess.STDOUT)

def run_with_server():
    command = gdb_with_script(pyafter='import pwndbg;\npwndbg.server.serve()')
    return subprocess.Popen(command, stdout=subprocess.PIPE)

gdb_with_server = run_with_server()
server = xmlhacks.xmlrpclib.ServerProxy('http://127.0.0.1:8889', verbose=1)

atexit.register(lambda: gdb_with_server.kill())
