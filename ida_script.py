import threading
import xmlrpclib
from SimpleXMLRPCServer import SimpleXMLRPCServer

import idaapi
import idautils
import idc

xmlrpclib.Marshaller.dispatch[type(0L)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)
xmlrpclib.Marshaller.dispatch[type(0)] = lambda _, v, w: w("<value><i8>%d</i8></value>" % v)

port = 8888

orig_LineA = idc.LineA

def LineA(*a,**kw):
    v = orig_LineA(*a,**kw)
    if v and v.startswith('\x01\x04; '):
        v = v[4:]
    return v

idc.LineA = LineA

def register_module(module):
    for name, function in module.__dict__.items():
        if hasattr(function, '__call__'):
            server.register_function(function, name)

server = SimpleXMLRPCServer(('127.0.0.1', port), logRequests=True, allow_none=True)
register_module(idc)
register_module(idautils)
register_module(idaapi)
server.register_introspection_functions()

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
