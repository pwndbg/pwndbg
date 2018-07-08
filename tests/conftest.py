"""
This file should consist of global test fixtures.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import shlex
import subprocess

import pytest

try:
    import xmlrpc.client as xmlrpclib
except:
    import xmlrpclib


_port = int(os.environ.get('PWNDBG_TESTSERVER_PORT', 8719))


def _launch_gdb_testserver(binary_path):
    cmd = 'gdb - -silent - -nx - -nh - -command gdbinit.py --command tests/testserver.py'
    subprocess.check_output(shlex.split(cmd) + [binary_path])


class Invoker:
    def __init__(self):
        self._rpc = xmlrpclib.ServerProxy('http://127.0.0.1:%d/' % _port)

    def invoke(self, pwndbg_func, *args, **kwargs):
        return self._rpc.invoke(pwndbg_func.__module__, pwndbg_func.__name__, *args, **kwargs)


@pytest.fixture
def start_gdb():
    """
    Returns function that launches GDB and returns Pwndbg's testserver XMLRPC
    """
    def _start_gdb(binary_path):
        _launch_gdb_testserver(binary_path)
        return Invoker()

    return _start_gdb

"""
Python subprocess(GDB) -> stdin/stdout 

"""