"""
Prints structures in a manner similar to Windbg's "dt" command.
"""

import re

import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo


def get_type(v):
    t = v.type
    while not t.name:
        if t.code == gdb.TYPE_CODE_PTR:
            t = t.target()
    return t.name


def get_typename(t):
    return str(t)


def get_arrsize(f):
    t = f.type
    if t.code != gdb.TYPE_CODE_ARRAY:
        return 0
    t2 = t.target()
    s = t2.sizeof
    return int(t.sizeof / t2.sizeof)


def get_field_by_name(obj, field):
    # Dereference once
    if obj.type.code == gdb.TYPE_CODE_PTR:
        obj = obj.dereference()
    for f in re.split(r"(->|\.|\[\d+\])", field):
        if not f:
            continue
        if f == "->":
            obj = obj.dereference()
        elif f == ".":
            pass
        elif f.startswith("["):
            n = int(f.strip("[]"))
            obj = obj.cast(obj.dereference().type.pointer())
            obj += n
            obj = obj.dereference()
        else:
            obj = obj[f]
    return obj


def happy(typename):
    prefix = ""
    if "unsigned" in typename:
        prefix = "u"
        typename = typename.replace("unsigned ", "")
    return (
        prefix
        + {
            "char": "char",
            "short int": "short",
            "long int": "long",
            "int": "int",
            "long long": "longlong",
            "float": "float",
            "double": "double",
        }[typename]
    )


def dt(name="", addr=None, obj=None):
    """
    Dump out a structure type Windbg style.
    """
    # Return value is a list of strings.of
    # We concatenate at the end.
    rv = []

    if obj and not name:
        t = obj.type
        while t.code == (gdb.TYPE_CODE_PTR):
            t = t.target()
            obj = obj.dereference()
        name = str(t)

    # Lookup the type name specified by the user
    else:
        t = pwndbg.gdblib.typeinfo.load(name)

    # If it's not a struct (e.g. int or char*), bail
    if t.code not in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_TYPEDEF, gdb.TYPE_CODE_UNION):
        raise Exception("Not a structure: %s" % t)

    # If an address was specified, create a Value of the
    # specified type at that address.
    if addr is not None:
        obj = pwndbg.gdblib.memory.poi(t, addr)

    # Header, optionally include the name
    header = name
    if obj:
        header = "%s @ %s" % (header, hex(int(obj.address)))
    rv.append(header)

    if t.strip_typedefs().code == gdb.TYPE_CODE_ARRAY:
        return "Arrays not supported yet"
    if t.strip_typedefs().code not in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
        t = {name: obj or gdb.Value(0).cast(t)}

    for name, field in t.items():
        # Offset into the parent structure
        o = getattr(field, "bitpos", 0) // 8
        b = getattr(field, "bitpos", 0) % 8
        extra = str(field.type)
        ftype = field.type.strip_typedefs()

        if obj and obj.type.strip_typedefs().code in (gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION):
            v = obj[name]

            if ftype.code == gdb.TYPE_CODE_INT:
                v = hex(int(v))
            if (
                ftype.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY)
                and ftype.target() == pwndbg.gdblib.typeinfo.uchar
            ):
                data = pwndbg.gdblib.memory.read(v.address, ftype.sizeof)
                v = " ".join("%02x" % b for b in data)

            extra = v

        # Adjust trailing lines in 'extra' to line up
        # This is necessary when there are nested structures.
        # Ideally we'd expand recursively if the type is complex.
        extra_lines = []
        for i, line in enumerate(str(extra).splitlines()):
            if i == 0:
                extra_lines.append(line)
            else:
                extra_lines.append(35 * " " + line)
        extra = "\n".join(extra_lines)

        bitpos = "" if not b else (".%i" % b)

        line = "    +0x%04x%s %-20s : %s" % (o, bitpos, name, extra)
        rv.append(line)

    return "\n".join(rv)
