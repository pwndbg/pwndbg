#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import codecs
import threading

import gdb
import pwndbg.config
import pwndbg.xmlhacks

pwndbg.xmlhacks.register_integer_type(gdb.Value)

host = pwndbg.config.Parameter('rpc-host', '127.0.0.1', 'xmlrpc server address')
port = pwndbg.config.Parameter('rpc-port', 8889, 'xmlrpc server port')

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

