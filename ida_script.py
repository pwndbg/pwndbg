#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import datetime
import threading
import xmlrpc.client as xmlclient
from xml.sax.saxutils import escape
from xmlrpc.server import SimpleXMLRPCServer

import idaapi
import idc

# Wait for any processing to get done
idaapi.auto_wait()

# On Windows with NTFS filesystem a filepath with ':'
# is treated as NTFS ADS (Alternative Data Stream)
# and so saving file with such name fails
dt = datetime.datetime.now().isoformat().replace(":", "-")

# Save the database so nothing gets lost.
idc.save_database(idc.get_idb_path() + "." + dt)


DEBUG_MARSHALLING = False


def create_marshaller(use_format=None, just_to_str=False):
    assert (
        use_format or just_to_str
    ), "Either pass format to use or make it converting the value to str."

    def wrapper(_marshaller, value, appender):
        if use_format:
            marshalled = use_format % value
        elif just_to_str:
            marshalled = "<value><string>%s</string></value>" % escape(str(value))

        if DEBUG_MARSHALLING:
            print("Marshalled: '%s'" % marshalled)

        appender(marshalled)

    return wrapper


xmlclient.Marshaller.dispatch[type(1 << 63)] = create_marshaller("<value><i8>%d</i8></value>")
xmlclient.Marshaller.dispatch[type(0)] = create_marshaller("<value><i8>%d</i8></value>")
xmlclient.Marshaller.dispatch[idaapi.cfuncptr_t] = create_marshaller(just_to_str=True)

host = "127.0.0.1"
port = 31337

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
            if f == idc.set_color:
                flags |= idaapi.MFF_NOWAIT
                rv.append(None)
            idaapi.execute_sync(work, flags)

        if error:
            msg = "Failed on calling {}.{} with args: {}, kwargs: {}\nException: {}".format(
                f.__module__, f.__name__, a, kw, str(error[0])
            )
            print("[!!!] ERROR:", msg)
            raise error[0]

        return rv[0]

    return wrapper


def register_module(module):
    for name, function in module.__dict__.items():
        if hasattr(function, "__call__"):
            server.register_function(wrap(function), name)


def decompile(addr):
    """
    Function that overwrites `idaapi.decompile` for xmlrpc so that instead
    of throwing an exception on `idaapi.DecompilationFailure` it just returns `None`.
    (so that we don't have to parse xmlrpc Fault's exception string on pwndbg side
    as it differs between IDA versions).
    """
    try:
        return idaapi.decompile(addr)
    except idaapi.DecompilationFailure:
        return None


def get_decompile_coord_by_ea(cfunc, addr):
    if idaapi.IDA_SDK_VERSION >= 720:
        item = cfunc.body.find_closest_addr(addr)
        y_holder = idaapi.int_pointer()
        if not cfunc.find_item_coords(item, None, y_holder):
            return None
        y = y_holder.value()
    else:
        lnmap = {}
        for i, line in enumerate(cfunc.pseudocode):
            phead = idaapi.ctree_item_t()
            pitem = idaapi.ctree_item_t()
            ptail = idaapi.ctree_item_t()
            ret = cfunc.get_line_item(line.line, 0, True, phead, pitem, ptail)
            if ret and pitem.it:
                lnmap[pitem.it.ea] = i
        y = None
        closest_ea = idaapi.BADADDR
        for ea, line in lnmap.items():
            if closest_ea == idaapi.BADADDR or abs(closest_ea - addr) > abs(ea - addr):
                closest_ea = ea
                y = lnmap[ea]

    return y


def decompile_context(addr, context_lines):
    cfunc = decompile(addr)
    if cfunc is None:
        return None
    y = get_decompile_coord_by_ea(cfunc, addr)
    if y is None:
        return cfunc
    lines = cfunc.get_pseudocode()
    retlines = []
    for lnnum in range(max(0, y - context_lines), min(len(lines), y + context_lines)):
        retlines.append(idaapi.tag_remove(lines[lnnum].line))
        if lnnum == y:
            retlines[-1] = ">" + retlines[-1][1:]
    return "\n".join(retlines)


def versions():
    """Returns IDA & Python versions"""
    import sys

    return {
        "python": sys.version,
        "ida": idaapi.get_kernel_version(),
        "hexrays": idaapi.get_hexrays_version() if idaapi.init_hexrays_plugin() else None,
    }


server = SimpleXMLRPCServer((host, port), logRequests=False, allow_none=True)
register_module(idaapi)
register_module(
    idc
)  # prioritize idc functions over above (e.g. idc.get_next_seg/ida_segment.get_next_seg)

server.register_function(lambda a: eval(a, globals(), locals()), "eval")
server.register_function(wrap(decompile))  # overwrites idaapi/ida_hexrays.decompile
server.register_function(wrap(decompile_context), "decompile_context")  # support context decompile
server.register_function(wrap(versions))
server.register_introspection_functions()

print("IDA Pro xmlrpc hosted on http://%s:%s" % (host, port))
print("Call `shutdown()` to shutdown the IDA Pro xmlrpc server.")

thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()


def shutdown():
    global server
    global thread
    server.shutdown()
    server.server_close()
    del server
    del thread
