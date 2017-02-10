#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import datetime
import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

import idaapi
import idautils
import idc

# Wait for any processing to get done
idaapi.autoWait()

# On Windows with NTFS filesystem a filepath with ':'
# is treated as NTFS ADS (Alternative Data Stream)
# and so saving file with such name fails
dt = datetime.datetime.now().isoformat().replace(':', '-')

# Save the database so nothing gets lost.
idc.SaveBase(idc.GetIdbPath() + '.' + dt)

xmlrpclib.Marshaller.dispatch[type(0L)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)
xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

host = '127.0.0.1'
port = 8888
orig_LineA = idc.LineA


def LineA(*a, **kw):
    v = orig_LineA(*a, **kw)
    if v and v.startswith('\x01\x04; '):
        v = v[4:]
    return v


idc.LineA = LineA

mutex = threading.Condition()


def wrap(f):
    def wrapper(*a, **kw):
        try:
            rv = []

            def work():
                rv.append(f(*a, **kw))

            with mutex:
                flags = idaapi.MFF_WRITE
                if f == idc.SetColor:
                    flags |= idaapi.MFF_NOWAIT
                    rv.append(None)
                idaapi.execute_sync(work, flags)
            return rv[0]
        except:
            import traceback
            traceback.print_exc()
            raise

    return wrapper


def register_module(module):
    for name, function in module.__dict__.items():
        if hasattr(function, '__call__'):
            server.register_function(wrap(function), name)


server = SimpleXMLRPCServer((host, port), logRequests=True, allow_none=True)
register_module(idc)
register_module(idautils)
register_module(idaapi)
server.register_function(lambda a: eval(a, globals(), locals()), 'eval')
server.register_introspection_functions()

print('Ida Pro xmlrpc hosted on http://%s:%s' % (host, port))

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
