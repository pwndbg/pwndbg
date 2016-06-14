from __future__ import print_function

import datetime
import functools
import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

import idaapi
import idautils
import idc

# Wait for any processing to get done
idaapi.autoWait()

# Save the database so nothing gets lost.
idc.SaveBase(idc.GetIdbPath() + '.' + datetime.datetime.now().isoformat())

xmlrpclib.Marshaller.dispatch[type(0L)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)
xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

port       = 8888
orig_LineA = idc.LineA

def LineA(*a,**kw):
    v = orig_LineA(*a,**kw)
    if v and v.startswith('\x01\x04; '):
        v = v[4:]
    return v

idc.LineA = LineA

mutex = threading.Condition()

def wrap(f):
    def wrapper(*a, **kw):
        try:
            rv = []
            def work(): rv.append(f(*a,**kw))
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

server = SimpleXMLRPCServer(('127.0.0.1', port), logRequests=True, allow_none=True)
register_module(idc)
register_module(idautils)
register_module(idaapi)
server.register_function(lambda a: eval(*a, globals(), locals()), 'eval')
server.register_introspection_functions()

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
