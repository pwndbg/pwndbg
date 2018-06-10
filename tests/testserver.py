"""
TODO / FIXME
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import shlex

from subprocess import Popen, PIPE, STDOUT

import gdb

try:
    from xmlrpc.server import SimpleXMLRPCServer
except:
    from SimpleXMLRPCServer import SimpleXMLRPCServer


port = int(os.environ.get('PWNDBG_TESTSERVER_PORT', 8719))

server = SimpleXMLRPCServer(('127.0.0.1', port), logRequests=True, allow_none=True)


def start_gdb(binary_path):
    cmd = 'gdb - -silent - -nx - -nh - -command gdbinit.py'
    gdb_process = Popen(shlex.split(cmd) + [binary_path], stdin=PIPE, stdout=PIPE, stderr=STDOUT)


def invoke(module_path, func_name, *args, **kwargs):
    func = __import__('%s.%s' % (module_path, func_name))
    return func(*args, **kwargs)


def gdb_execute(string, to_string=False):
    return gdb.execute(string, to_string=to_string)


server.register_function(invoke, 'invoke')
server.register_function(gdb_execute)
server.register_introspection_functions()

server.serve_forever()
