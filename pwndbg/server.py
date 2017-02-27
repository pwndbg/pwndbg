#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import threading

import gdb
import pwndbg
import pwndbg.xmlhacks

pwndbg.xmlhacks.register_integer_type(gdb.Value)

host = pwndbg.config.Parameter('rpc-host', '127.0.0.1', 'xmlrpc server address')
port = pwndbg.config.Parameter('rpc-port', 8889, 'xmlrpc server port')

def string_test():
    return "String\x00Bar"

def int_test():
    return 17

def long_test():
    return 1 << 100

def bytes_test():
    return b'asdf'

def bytearray_test():
    return bytearray(b'asdfasdf')

def string_test():
    return "Hello"

def string_with_null_test():
    return "Hello\x00World"

def unicode_test():
    return "☠"

def megatest():
    return [int_test(),
            long_test(),
            bytes_test(),
            bytearray_test(),
            string_test(),
            string_with_null_test(),
            unicode_test()]

def serve():
    server = pwndbg.xmlhacks.SimpleXMLRPCServer((str(host), int(port)), logRequests=True, allow_none=True)
    server.register_instance(gdb, allow_dotted_names=True)
    server.register_instance(pwndbg, allow_dotted_names=True)
    server.register_function(lambda a: eval(a, globals(), locals()), 'eval')
    server.register_introspection_functions()

    print("Starting server on %s:%s" % (host, port))

    # thread = threading.Thread(target=server.serve_forever)
    # thread.daemon = True
    # thread.start()
    server.serve_forever()

