"""
Prints structures in a manner similar to WinDbg's "dt" command.
"""

from __future__ import annotations

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod


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


def _append_field_lines(
    rv: list[str],
    t: pwndbg.dbg_mod.Type,
    obj: pwndbg.dbg_mod.Value | None,
    *,
    base_offset: int,
    base_address: int | None,
    indent: str,
) -> None:
    fields = t.fields()
    has_bitfields = any(f.bitpos % 8 != 0 for f in fields)
    for field in fields:
        field_name = field.name
        field_label = field_name if field_name is not None else "<anonymous>"

        # Offset into the top-level structure.
        offset = field.bitpos // 8
        absolute_offset = base_offset + offset
        bitpos = field.bitpos % 8
        ftype = field.type.strip_typedefs()
        extra = _field_to_human(field)
        is_nested_aggregate = ftype.code in (
            pwndbg.dbg_mod.TypeCode.STRUCT,
            pwndbg.dbg_mod.TypeCode.UNION,
        )
        nested_obj: pwndbg.dbg_mod.Value | None = None

        if obj and obj.type.strip_typedefs().code in (
            pwndbg.dbg_mod.TypeCode.STRUCT,
            pwndbg.dbg_mod.TypeCode.UNION,
        ):
            try:
                if field_name is not None:
                    nested_obj = obj[field_name]

                if nested_obj is not None:
                    if ftype.code == pwndbg.dbg_mod.TypeCode.INT:
                        extra = hex(int(nested_obj))
                    elif (
                        ftype.code
                        in (pwndbg.dbg_mod.TypeCode.POINTER, pwndbg.dbg_mod.TypeCode.ARRAY)
                        and ftype.target() == pwndbg.aglib.typeinfo.uchar
                    ):
                        # Flexible array members have size 0, skip reading memory for them.
                        if ftype.sizeof == 0:
                            extra = "[]"
                        else:
                            data = pwndbg.aglib.memory.read(int(nested_obj.address), ftype.sizeof)
                            extra = " ".join(f"{b:02x}" for b in data)
                    elif not is_nested_aggregate:
                        extra = nested_obj.value_to_human_readable()
            except pwndbg.dbg_mod.Error:
                raise

        if is_nested_aggregate:
            extra = f"{extra} {{"

        # Adjust trailing lines in 'extra' to line up.
        extra_lines: list[str] = []
        extra_padding = len(indent) + 31 + (2 if has_bitfields else 0)
        for i, line in enumerate(str(extra).splitlines()):
            if i == 0:
                extra_lines.append(line)
            else:
                extra_lines.append(extra_padding * " " + line)
        extra = "\n".join(extra_lines)

        if bitpos:
            bitpos_str = f".{bitpos}"
        elif has_bitfields:
            bitpos_str = "  "
        else:
            bitpos_str = ""

        if base_address is not None:
            line = f"{indent}0x{base_address + absolute_offset:016x} +0x{absolute_offset:04x}{bitpos_str} {field_label:<20} : {extra}"
        else:
            line = f"{indent}+0x{absolute_offset:04x}{bitpos_str} {field_label:<20} : {extra}"
        rv.append(line)

        if is_nested_aggregate:
            _append_field_lines(
                rv,
                ftype,
                nested_obj,
                base_offset=absolute_offset,
                base_address=base_address,
                indent=indent + "    ",
            )
            rv.append(f"{indent}}}")


def dt(
    name: str = "",
    addr: int | pwndbg.dbg_mod.Value | None = None,
    obj: pwndbg.dbg_mod.Value | None = None,
) -> str:
    """
    Dump out a structure type WinDbg style.
    """
    # Return value is a list of strings.of
    # We concatenate at the end.
    rv: list[str] = []

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
        return "Type not found."

    # If it's not a struct (e.g. int or char*), bail
    if t.strip_typedefs().code not in (
        pwndbg.dbg_mod.TypeCode.STRUCT,
        pwndbg.dbg_mod.TypeCode.UNION,
    ):
        return f"Not a structure: {t.strip_typedefs().name_to_human_readable}"

    # If an address was specified, create a Value of the
    # specified type at that address.
    if addr is not None:
        obj = pwndbg.aglib.memory.get_typed_pointer_value(t, addr)

    # Header, optionally include the name
    header = name
    if obj:
        header = f"{header} @ {hex(int(obj.address))}"
    rv.append(header)

    _append_field_lines(
        rv,
        t,
        obj,
        base_offset=0,
        base_address=int(obj.address) if obj else None,
        indent="    ",
    )

    return "\n".join(rv)
