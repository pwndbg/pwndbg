#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import os
import re
import subprocess
import tempfile

def get_type(v):
    t = v.type
    while not t.name:
        if t.code == gdb.TYPE_CODE_PTR:
            t = t.target()
    return t.name

def get_typename(t):
    return(str(t))

def get_arrsize(f):
    t = f.type
    if t.code != gdb.TYPE_CODE_ARRAY:
        return 0
    t2 = t.target()
    s  = t2.sizeof
    return int(t.sizeof / t2.sizeof)

def get_field_by_name(obj, field):
    # Dereference once
    if obj.type.code == gdb.TYPE_CODE_PTR:
        obj = obj.dereference()
    for f in re.split('(->|\.|\[\d+\])', field):
        if not f: continue
        if f   == '->':
            obj = obj.dereference()
        elif f == '.':
            pass
        elif f.startswith('['):
            n   = int(f.strip('[]'))
            obj = obj.cast(obj.dereference().type.pointer())
            obj += n
            obj = obj.dereference()
        else:
            obj = obj[f]
    return obj

def happy(typename):
    prefix = ''
    if 'unsigned' in typename:
        prefix = 'u'
        typename = typename.replace('unsigned ', '')
    return prefix + {
    'char': 'char',
    'short int': 'short',
    'long int': 'long',
    'int': 'int',
    'long long': 'longlong',
    'float': 'float',
    'double': 'double'
    }[typename]

def dt(name='', addr=None, obj = None):
    """
    Dump out a structure type Windbg style.
    """
    # Return value is a list of strings.of
    # We concatenate at the end.
    rv  = []

    if obj and not name:
        t = obj.type
        while t.code == (gdb.TYPE_CODE_PTR):
            t   = t.target()
            obj = obj.dereference()
        name = str(t)

    # Lookup the type name specified by the user
    else:
        t = gdb.lookup_type(name)

    # If it's not a struct (e.g. int or char*), bail
    if t.code not in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_TYPEDEF):
        raise Exception("Not a structure: %s" % t)

    # If an address was specified, create a Value of the
    # specified type at that address.
    if addr is not None:
        obj = gef.memory.poi(t, addr)

    # Header, optionally include the name
    header = name
    if obj: header = "%s @ %s" % (header, hex(int(obj.address)))
    rv.append(header)

    for name, field in t.items():
        # Offset into the parent structure
        o     = field.bitpos/8
        extra = str(field.type)
        if obj:
            v  = obj[name]
            if field.type.strip_typedefs().code == gdb.TYPE_CODE_INT:
                v = hex(int(v))
            extra = v

        line  = "    +0x%04x %-20s : %s" % (o, name, extra)
        rv.append(line)

    return ('\n'.join(rv))