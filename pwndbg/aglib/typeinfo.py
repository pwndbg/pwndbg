"""
Common types.
"""

from __future__ import annotations

import sys
from typing import Dict
from typing import Optional

import pwndbg

module = sys.modules[__name__]

char: pwndbg.dbg_mod.Type
ulong: pwndbg.dbg_mod.Type
long: pwndbg.dbg_mod.Type
uchar: pwndbg.dbg_mod.Type
ushort: pwndbg.dbg_mod.Type
uint: pwndbg.dbg_mod.Type
void: pwndbg.dbg_mod.Type

uint8: pwndbg.dbg_mod.Type
uint16: pwndbg.dbg_mod.Type
uint32: pwndbg.dbg_mod.Type
uint64: pwndbg.dbg_mod.Type
unsigned: Dict[int, pwndbg.dbg_mod.Type]

int8: pwndbg.dbg_mod.Type
int16: pwndbg.dbg_mod.Type
int32: pwndbg.dbg_mod.Type
int64: pwndbg.dbg_mod.Type
signed: Dict[int, pwndbg.dbg_mod.Type]

pvoid: pwndbg.dbg_mod.Type
ppvoid: pwndbg.dbg_mod.Type
pchar: pwndbg.dbg_mod.Type

ptrsize: int = 4

ptrdiff: pwndbg.dbg_mod.Type
size_t: pwndbg.dbg_mod.Type
ssize_t: pwndbg.dbg_mod.Type


def lookup_types(*types: str) -> pwndbg.dbg_mod.Type:
    process = pwndbg.dbg.selected_inferior()
    assert process, "tried to initialize typeinfo with no inferior"
    for type_str in types:
        t = process.types_with_name(type_str)
        if len(t) > 0:
            return t[0]

    raise RuntimeError(f"no type available among {types}")


def update() -> None:
    module.char = lookup_types("signed char", "char")
    module.ulong = lookup_types("unsigned long", "uint", "u32", "uint32")
    module.long = lookup_types("long", "int", "i32", "int32")
    module.uchar = lookup_types("unsigned char", "ubyte", "u8", "uint8")
    module.ushort = lookup_types("unsigned short", "ushort", "u16", "uint16", "uint16_t")
    module.uint = lookup_types("unsigned int", "uint", "u32", "uint32")
    module.void = lookup_types("void", "()")

    module.uint8 = module.uchar
    module.uint16 = module.ushort
    module.uint32 = module.uint
    module.uint64 = lookup_types("unsigned long long", "ulong", "u64", "uint64")
    module.unsigned = {
        1: module.uint8,
        2: module.uint16,
        4: module.uint32,
        8: module.uint64,
    }

    module.int8 = lookup_types("char", "i8", "int8")
    module.int16 = lookup_types("short", "short int", "i16", "int16")
    module.int32 = lookup_types("int", "i32", "int32")
    module.int64 = lookup_types("long long", "long long int", "long", "i64", "int64")
    module.signed = {1: module.int8, 2: module.int16, 4: module.int32, 8: module.int64}

    module.pvoid = void.pointer()
    module.ppvoid = pvoid.pointer()
    module.pchar = char.pointer()

    module.ptrsize = pvoid.sizeof

    if pvoid.sizeof == 4:
        module.ptrdiff = module.uint32
        module.size_t = module.uint32
        module.ssize_t = module.int32
    elif pvoid.sizeof == 8:
        module.ptrdiff = module.uint64
        module.size_t = module.uint64
        module.ssize_t = module.int64
    else:
        raise Exception("Pointer size not supported")


def load(name: str) -> Optional[pwndbg.dbg_mod.Type]:
    """Load a symbol; note that new symbols can be added with `add-symbol-file` functionality"""
    names = pwndbg.dbg.selected_inferior().types_with_name(name)
    if len(names) > 0:
        return names[0]
    return None


def get_type(size: int) -> pwndbg.dbg_mod.Type:
    return {
        1: pwndbg.aglib.typeinfo.uint8,
        2: pwndbg.aglib.typeinfo.uint16,
        4: pwndbg.aglib.typeinfo.uint32,
        8: pwndbg.aglib.typeinfo.uint64,
    }[size]
