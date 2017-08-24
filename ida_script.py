#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import datetime
import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer
from xml.sax.saxutils import escape

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
if idaapi.IDA_SDK_VERSION >= 700:
    idaapi.save_database(idc.GetIdbPath() + '.' + dt)
else:
    idc.SaveBase(idc.GetIdbPath() + '.' + dt)


DEBUG_MARSHALLING = False

def create_marshaller(use_format=None, just_to_str=False):
    assert use_format or just_to_str, 'Either pass format to use or make it converting the value to str.'

    def wrapper(_marshaller, value, appender):
        if use_format:
            marshalled = use_format % value
        elif just_to_str:
            marshalled = '<value><string>%s</string></value>' % escape(str(value))

        if DEBUG_MARSHALLING:
            print("Marshalled: '%s'" % marshalled)

        appender(marshalled)

    return wrapper

xmlrpclib.Marshaller.dispatch[type(0L)] = create_marshaller("<value><i8>%d</i8></value>")
xmlrpclib.Marshaller.dispatch[type(0)] = create_marshaller("<value><i8>%d</i8></value>")
xmlrpclib.Marshaller.dispatch[idaapi.cfuncptr_t] = create_marshaller(just_to_str=True)

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
        rv = []
        error = []

        def work():
            try:
                result = f(*a, **kw)
                rv.append(result)
            except Exception as e:
                error.append(e)

        with mutex:
            flags = idaapi.MFF_WRITE
            if f == idc.SetColor:
                flags |= idaapi.MFF_NOWAIT
                rv.append(None)
            idaapi.execute_sync(work, flags)

        if error:
            msg = 'Failed on calling {}.{} with args: {}, kwargs: {}\nException: {}' \
                .format(f.__module__, f.__name__, a, kw, str(error[0]))
            print('[!!!] ERROR:', msg)
            raise error[0]

        return rv[0]

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
