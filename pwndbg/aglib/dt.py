"""
Prints structures in a manner similar to Windbg's "dt" command.
"""

from __future__ import annotations

from typing import List

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.dbg


def _field_to_human(
    f: pwndbg.dbg_mod.TypeField | pwndbg.dbg_mod.Value | pwndbg.dbg_mod.Type,
) -> str:
    if isinstance(f, pwndbg.dbg_mod.TypeField):
        t = f.type
    elif isinstance(f, pwndbg.dbg_mod.Type):
        t = f
    elif isinstance(f, pwndbg.dbg_mod.Value):
        t = f.type
    else:
        raise NotImplementedError("unknown type")

    return t.name_to_human_readable


def dt(
    name: str = "",
    addr: int | pwndbg.dbg_mod.Value | None = None,
    obj: pwndbg.dbg_mod.Value | None = None,
) -> str:
    """
    Dump out a structure type Windbg style.
    """
    # Return value is a list of strings.of
    # We concatenate at the end.
    rv: List[str] = []

    if obj and not name:
        t = obj.type
        while t.code == pwndbg.dbg_mod.TypeCode.POINTER:
            t = t.target()
            obj = obj.dereference()
        name = str(t)

    # Lookup the type name specified by the user
    else:
        t = pwndbg.aglib.typeinfo.load(name)

    if not t:
        return ""

    # If it's not a struct (e.g. int or char*), bail
    if t.code not in (
        pwndbg.dbg_mod.TypeCode.STRUCT,
        pwndbg.dbg_mod.TypeCode.TYPEDEF,
        pwndbg.dbg_mod.TypeCode.UNION,
    ):
        return f"Not a structure: {t}"

    # If an address was specified, create a Value of the
    # specified type at that address.
    if addr is not None:
        obj = pwndbg.aglib.memory.get_typed_pointer_value(t, addr)

    # Header, optionally include the name
    header = name
    if obj:
        header = f"{header} @ {hex(int(obj.address))}"
    rv.append(header)

    if t.strip_typedefs().code == pwndbg.dbg_mod.TypeCode.ARRAY:
        return "Arrays not supported yet"

    if t.strip_typedefs().code not in (
        pwndbg.dbg_mod.TypeCode.STRUCT,
        pwndbg.dbg_mod.TypeCode.UNION,
    ):
        newobj = obj
        if not newobj:
            newobj = pwndbg.dbg.selected_inferior().create_value(0, t)

        iter_fields = [(field.name, field) for field in newobj.type.fields()]
    else:
        iter_fields = [(field.name, field) for field in t.fields()]

    for field_name, field in iter_fields:
        # Offset into the parent structure
        offset = field.bitpos // 8
        bitpos = field.bitpos % 8
        ftype = field.type.strip_typedefs()
        extra = _field_to_human(field)

        if obj and obj.type.strip_typedefs().code in (
            pwndbg.dbg_mod.TypeCode.STRUCT,
            pwndbg.dbg_mod.TypeCode.UNION,
        ):
            obj_value = obj[field_name]
            if ftype.code == pwndbg.dbg_mod.TypeCode.INT:
                extra = hex(int(obj_value))
            elif (
                ftype.code in (pwndbg.dbg_mod.TypeCode.POINTER, pwndbg.dbg_mod.TypeCode.ARRAY)
                and ftype.target() == pwndbg.aglib.typeinfo.uchar
            ):
                data = pwndbg.aglib.memory.read(int(obj_value.address), ftype.sizeof)
                extra = " ".join("%02x" % b for b in data)
            else:
                extra = obj_value.value_to_human_readable()

        # Adjust trailing lines in 'extra' to line up
        # This is necessary when there are nested structures.
        # Ideally we'd expand recursively if the type is complex.
        extra_lines: List[str] = []
        for i, line in enumerate(str(extra).splitlines()):
            if i == 0:
                extra_lines.append(line)
            else:
                extra_lines.append(35 * " " + line)
        extra = "\n".join(extra_lines)

        bitpos_str = "" if not bitpos else (".%i" % bitpos)

        if obj:
            line = "    0x%016x +0x%04x%s %-20s : %s" % (
                int(obj.address) + offset,
                offset,
                bitpos_str,
                field_name,
                extra,
            )
        else:
            line = "    +0x%04x%s %-20s : %s" % (offset, bitpos_str, field_name, extra)
        rv.append(line)

    return "\n".join(rv)
