from __future__ import annotations

import string
import struct
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from dataclasses import field
from enum import IntEnum
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from typing import cast

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.elf
import pwndbg.gdblib.file
import pwndbg.gdblib.memory
import pwndbg.gdblib.proc
import pwndbg.gdblib.symbol
import pwndbg.hexdump
import pwndbg.lib.cache
from pwndbg.color import message


@pwndbg.lib.cache.cache_until("start", "stop", "objfile")
def word_size() -> int:
    """
    Gets the Go word size for the current architecture.

    Values taken from https://github.com/golang/go/blob/20b79fd5775c39061d949569743912ad5e58b0e7/src/go/types/sizes.go#L233-L252
    """
    return {"i386": 4, "x86-64": 8, "aarch64": 8, "arm": 4, "rv64": 8, "powerpc": 8, "sparc": 8}[
        pwndbg.gdblib.arch.name
    ]


def _align(offset: int, n: int) -> int:
    ret = offset + n - 1
    return ret - ret % n


def compute_offsets(fields: List[Tuple[int, int]]) -> List[int]:
    """
    Given a list of (size, alignment) for struct field types,
    returns a list of field offsets for the struct.
    The last element will be the offset of the struct's end (the struct size).

    Layout computation taken from src/go/types/sizes.go commit 1b4f1dc
    """
    cur = 0
    ret = []
    max_align = 1
    for s, a in fields:
        cur = _align(cur, a)
        ret.append(cur)
        cur += s
        max_align = max(max_align, a)
    cur = _align(cur, max_align)
    ret.append(cur)
    return ret


def compute_named_offsets(fields: List[Tuple[str, int, int]]) -> Dict[str, int]:
    """
    Like compute_offsets, but takes in field names and returns a dictionary
    mapping field name to offset instead.

    Also maps in a special $size field with the size of the struct.
    """
    offsets = compute_offsets([f[1:] for f in fields])
    ret = dict(zip([f[0] for f in fields] + ["$size"], offsets))
    return ret


class Type(ABC):
    @abstractmethod
    def dump(self, addr: int, fmt: str = "") -> str:
        """Dump a type from memory given an address and format."""
        pass

    @abstractmethod
    def size(self) -> int:
        """
        Returns the size of a type in bytes.

        Used for computing array and struct layouts.
        """
        pass


def load_uint(data: bytes) -> int:
    return int.from_bytes(data, pwndbg.gdblib.arch.endian)


def load_int(data: bytes) -> int:
    n = load_uint(data)
    wrap = 1 << (len(data) * 8 - 1)
    if n >= wrap:
        n -= wrap * 2
    return n


def load_float(data: bytes) -> float:
    endian = ">" if pwndbg.gdblib.arch.endian == "big" else "<"
    if len(data) == 4:
        return struct.unpack(endian + "f", data)[0]
    if len(data) == 8:
        return struct.unpack(endian + "d", data)[0]
    raise ValueError("Invalid float length")


def _try_format(val: Any, fmt: str):
    try:
        return format(val, fmt)
    except ValueError:
        return format(val)


# only warn with a given message once per execution
@pwndbg.lib.cache.cache_until("start")
def emit_warning(msg: str):
    print(message.warn(msg))


@pwndbg.lib.cache.cache_until("objfile")
def get_moduledata_types(addr: int | None = None) -> int | None:
    first_start = None
    # try to get type start by traversing moduledata symbol
    # will only work if debug symbols are enabled
    try:
        sym = gdb.lookup_symbol("runtime.firstmoduledata")[0]
        if sym is not None:
            md = sym.value()
            while True:
                start = int(md["types"])
                if first_start is None:
                    first_start = start
                end = int(md["etypes"])
                if addr is None or start <= addr < end:
                    return start
                if md["next"]:
                    md = md["next"].dereference()
                else:
                    emit_warning(
                        f"Warning: Type at {addr:#x} is out of bounds of all module data, so a heuristic is used instead"
                    )
                    break
        else:
            emit_warning(
                "Warning: Could not find `runtime.firstmoduledata` symbol, so a heuristic is used instead"
            )
    except gdb.error as e:
        emit_warning(
            f"Warning: Exception '{e}' occurred while trying to parse `runtime.firstmoduledata`, so a heuristic is used instead"
        )
    # if we found at least one moduledata, use the start of the first one
    if first_start is not None:
        return first_start
    # the type:* symbol can also indicate type start
    type_start = pwndbg.gdblib.symbol.address("type:*")
    if type_start is not None:
        return type_start
    # otherwise, just assume that types are at the start of .rodata if there aren't any debug symbols
    # not a great workaround, but parsing moduledata manually is very version-dependent
    elf = pwndbg.gdblib.elf.get_elf_info_rebased(
        pwndbg.gdblib.file.get_proc_exe_file(), pwndbg.gdblib.proc.binary_base_addr
    )
    addr = next((cast(int, x["sh_addr"]) for x in elf.sections if x["x_name"] == ".rodata"), None)
    return addr


def read_varint_str(addr: int) -> bytes:
    """
    Read a length-prefix string encoded with Go's variable length encoding.

    Implementation taken from https://github.com/golang/go/blob/9d33956503c0d96c0c5666d374173f7ac9756d98/src/internal/abi/type.go#L640-L649
    """
    orig_addr = addr
    strlen = 0
    while True:
        b = pwndbg.gdblib.memory.read(addr, 1)[0]
        strlen = (strlen << 7) | (b & 0x7F)
        if b == 0x80 or strlen > 0x1000:
            # we're probably not actually reading a varint str and should just return some bytes to avoid infinite looping
            return pwndbg.gdblib.memory.read(orig_addr, 16)
        addr += 1
        if not (b & 0x80):
            break
    # pwndbg.gdblib.memory.read doesn't support 0-length reads
    if strlen == 0:
        return b""
    return pwndbg.gdblib.memory.read(addr, strlen)


class GoTypeKind(IntEnum):
    INVALID = 0
    BOOL = 1
    INT = 2
    INT8 = 3
    INT16 = 4
    INT32 = 5
    INT64 = 6
    UINT = 7
    UINT8 = 8
    UINT16 = 9
    UINT32 = 10
    UINT64 = 11
    UINTPTR = 12
    FLOAT32 = 13
    FLOAT64 = 14
    COMPLEX64 = 15
    COMPLEX128 = 16
    ARRAY = 17
    CHAN = 18
    FUNC = 19
    INTERFACE = 20
    MAP = 21
    POINTER = 22
    SLICE = 23
    STRING = 24
    STRUCT = 25
    UNSAFEPOINTER = 26

    def get_simple_name(self) -> str | None:
        # Gets the name of a simple type
        if self.BOOL <= self <= self.COMPLEX128:
            return self.name.lower()
        if self == self.STRING:
            return "string"
        if self == self.UNSAFEPOINTER:
            return "uintptr"
        return None


@dataclass
class GoTypeMeta:
    name: str
    kind: GoTypeKind
    size: int = 0
    align: int = 1
    direct_iface: bool = False


def decode_runtime_type(addr: int) -> Tuple[GoTypeMeta, Type | None]:
    """
    Decodes a runtime reflection type from memory, returning a (meta, type) tuplee.

    The layout assumed is as follows (taken from src/internal/abi/type.go commit 1b4f1dc):

    type Type struct {
        Size_       uintptr
        PtrBytes    uintptr
        Hash        uint32
        TFlag       TFlag
        Align_      uint8
        FieldAlign_ uint8
        Kind_       Kind
        Equal       func(unsafe.Pointer, unsafe.Pointer) bool
        GCData      *byte
        Str         NameOff
        PtrToThis   TypeOff
    }
    """
    word = word_size()
    offsets = compute_named_offsets(
        [
            ("Size_", word, word),  # uintptr
            ("PtrBytes", word, word),  # uintptr
            ("Hash", 4, 4),  # uint32
            ("TFlag", 1, 1),  # TFlag (alias for uint8)
            ("Align_", 1, 1),  # uint8
            ("FieldAlign_", 1, 1),  # uint8
            ("Kind_", 1, 1),  # Kind (alias for uint8)
            ("Equal", word, word),  # funcptr
            ("GCData", word, word),  # *byte
            ("Str", 4, 4),  # NameOff (alias for int32)
            ("PtrToThis", 4, 4),  # TypeOff (alias for int32)
        ]
    )
    load = lambda off, sz: load_uint(pwndbg.gdblib.memory.read(addr + off, sz))
    type_start = get_moduledata_types(addr)
    if type_start is None:
        name = "unknown name"
    else:
        name_ptr = type_start + load(offsets["Str"], 4)
        bname = read_varint_str(name_ptr + 1)
        try:
            name = bname.decode()
        except UnicodeDecodeError:
            name = repr(bname)
    kind_raw = load(offsets["Kind_"], 1)
    # KindMask is set to (1 << 5) - 1
    try:
        kind = GoTypeKind(kind_raw & ((1 << 5) - 1))
    except ValueError:
        kind = GoTypeKind.INVALID
    if kind == GoTypeKind.INVALID:
        return (GoTypeMeta(f"invalid type `{name}` at {addr:#x}", kind), None)
    # Go puts * in front of a lot of types for some reason, so get rid of them for non-pointers
    if name.startswith("*") and kind != GoTypeKind.POINTER:
        name = name.lstrip("*")
    size = load(offsets["Size_"], word)
    align = load(offsets["Align_"], 1)
    meta = GoTypeMeta(name, kind, size=size, align=align, direct_iface=(kind_raw & (1 << 5)) != 0)
    simple_name = kind.get_simple_name()
    if simple_name is not None:
        return (meta, BasicType(simple_name))
    if kind == GoTypeKind.ARRAY:
        elem_ty_ptr = load(offsets["$size"], word)
        arr_len = load(offsets["$size"] + word * 2, word)
        elem_meta, elem_ty = decode_runtime_type(elem_ty_ptr)
        # reserialize name to fix inconsistencies
        meta.name = f"[{arr_len}]{elem_meta.name}"
        return (meta, elem_ty and ArrayType(elem_ty, arr_len))
    elif kind == GoTypeKind.INTERFACE:
        methods_count = load(offsets["$size"] + word * 2, word)
        if methods_count == 0:
            return (meta, BasicType("any"))
        else:
            return (meta, BasicType("interface"))
    elif kind == GoTypeKind.MAP:
        key_ty_ptr = load(offsets["$size"], word)
        val_ty_ptr = load(offsets["$size"] + word, word)
        key_meta, key_ty = decode_runtime_type(key_ty_ptr)
        if key_ty is None:
            return (meta, None)
        val_meta, val_ty = decode_runtime_type(val_ty_ptr)
        if val_ty is None:
            return (meta, None)
        # reserialize name to fix inconsistencies
        meta.name = f"map[{key_meta.name}]{val_meta.name}"
        # Go maps are actually pointers, but the map here is not
        return (meta, PointerType(MapType(key_ty, val_ty)))
    elif kind == GoTypeKind.POINTER:
        elem_ty_ptr = load(offsets["$size"], word)
        elem_meta, elem_ty = decode_runtime_type(elem_ty_ptr)
        # reserialize name to fix inconsistencies
        meta.name = f"*{elem_meta.name}"
        return (meta, elem_ty and PointerType(elem_ty))
    elif kind == GoTypeKind.SLICE:
        elem_ty_ptr = load(offsets["$size"], word)
        elem_meta, elem_ty = decode_runtime_type(elem_ty_ptr)
        # reserialize name to fix inconsistencies
        meta.name = f"[]{elem_meta.name}"
        return (meta, elem_ty and SliceType(elem_ty))
    elif kind == GoTypeKind.STRUCT:
        fields_ptr = load(offsets["$size"] + word, word)
        fields_count = load(offsets["$size"] + word * 2, word)
        fields: List[Tuple[str, Type | str, int]] = []
        for i in range(fields_count):
            base = fields_ptr + i * word * 3
            bfield_name = read_varint_str(load_uint(pwndbg.gdblib.memory.read(base, word)) + 1)
            try:
                field_name = bfield_name.decode()
            except UnicodeDecodeError:
                field_name = repr(bfield_name)
            field_ty_ptr = load_uint(pwndbg.gdblib.memory.read(base + word, word))
            field_off = load_uint(pwndbg.gdblib.memory.read(base + word * 2, word))
            (field_meta, field_ty) = decode_runtime_type(field_ty_ptr)
            if field_ty is None:
                field_ty = field_meta.name
            fields.append((field_name, field_ty, field_off))
        fields.sort(key=lambda f: f[2])
        sz = load(offsets["Size_"], word)
        return (meta, StructType(fields, sz, None if name.startswith("struct ") else name))
    else:
        # currently channels and functions are unsupported
        return (meta, None)


@dataclass
class BasicType(Type):
    """
    A primitive Go type.

    Complex numbers are laid out as a real and imaginary part (both floats).
    Strings are laid out as a pointer and a length.
    """

    name: str
    sz: int = field(init=False)

    def dump(self, addr: int, fmt: str = "") -> str:
        val = pwndbg.gdblib.memory.read(addr, self.size())
        ty = self.name
        if ty == "byte":
            ty = "uint8"
        elif ty == "rune":
            ty = "int32"
        if ty in ("any", "interface"):
            word = word_size()
            if ty == "interface":
                iface_ptr = load_uint(val[:word])
                if iface_ptr == 0:
                    return "nil"
                ty_ptr = load_uint(pwndbg.gdblib.memory.read(iface_ptr + word, word))
            else:
                ty_ptr = load_uint(val[:word])
            if ty_ptr == 0:
                return "nil"
            meta, parsed_inner = decode_runtime_type(ty_ptr)
            data_ptr = addr + word
            if not meta.direct_iface:
                data_ptr = load_uint(pwndbg.gdblib.memory.read(data_ptr, word))
            if data_ptr == 0:
                return f"({meta.name}) nil"
            if parsed_inner is not None:
                dump = parsed_inner.dump(data_ptr)
                return f"({meta.name}) {dump}"
            return f"({meta.name}) at {data_ptr:#x}"
        if ty == "bool":
            return "true" if val != b"\x00" else "false"
        if ty.startswith("int"):
            n = load_int(val)
            return _try_format(n, fmt)
        if ty.startswith("uint"):
            n = load_uint(val)
            return _try_format(n, fmt)
        if ty.startswith("float"):
            return _try_format(load_float(val), fmt)
        if ty.startswith("complex"):
            word = len(val) // 2
            real = _try_format(load_float(val[:word]), fmt)
            im = _try_format(load_float(val[word:]), fmt)
            return f"({real} + {im}i)"
        if ty == "string":
            word = word_size()
            ptr = load_uint(val[:word])
            strlen = load_uint(val[word:])
            # pwndbg.gdblib.memory.read doesn't support 0-length reads
            if strlen == 0:
                data = b""
            else:
                data = pwndbg.gdblib.memory.read(ptr, strlen)
            try:
                return repr(data.decode("utf8"))
            except UnicodeDecodeError:
                return repr(bytes(data))
        raise ValueError(f"Could not dump type {ty}.")

    def size(self) -> int:
        return self.sz

    def __str__(self) -> str:
        return self.name

    def __post_init__(self) -> None:
        ty = self.name
        if ty in ("int8", "uint8", "bool", "byte"):
            self.sz = 1
        elif ty in ("int16", "uint16"):
            self.sz = 2
        elif ty in ("int32", "uint32", "float32", "rune"):
            self.sz = 4
        elif ty in ("int64", "uint64", "float64", "complex64"):
            self.sz = 8
        elif ty == "complex128":
            self.sz = 16
        elif ty in ("int", "uint", "uintptr"):
            self.sz = word_size()
        elif ty == "string":
            self.sz = word_size() * 2
        elif ty in ("any", "interface"):
            self.sz = word_size() * 2
        else:
            raise ValueError(
                f"Type {ty} is unknown. Use type hexdump[n] for an unknown type of size n."
            )


@dataclass
class SliceType(Type):
    """
    A slice type in Go, notated as []inner.

    Slices are laid out as a pointer, length, and capacity.
    """

    inner: Type

    def dump(self, addr: int, fmt: str = "") -> str:
        word = word_size()
        val = pwndbg.gdblib.memory.read(addr, word * 3)
        ptr = load_uint(val[:word])
        slice_len = load_uint(val[word : word * 2])
        cap = load_uint(val[word * 2 :])
        ret = []
        for _ in range(slice_len):
            ret.append(self.inner.dump(ptr, fmt))
            ptr += self.inner.size()
        return f"(cap={cap}) [{', '.join(ret)}]"

    def size(self) -> int:
        return word_size() * 3

    def __str__(self) -> str:
        return f"[]{self.inner}"


@dataclass
class PointerType(Type):
    """
    A pointer type in Go, notated as *inner.
    """

    inner: Type

    def dump(self, addr: int, fmt: str = "") -> str:
        word = word_size()
        ptr = load_uint(pwndbg.gdblib.memory.read(addr, word))
        if ptr == 0:
            return "nil"
        inner = self.inner.dump(ptr, fmt)
        return f"&{inner}"

    def size(self) -> int:
        return word_size()

    def __str__(self) -> str:
        return f"*{self.inner}"


@dataclass
class ArrayType(Type):
    """
    An array type in Go, notated as [count]inner.

    Arrays are laid out as contiguous data.
    """

    inner: Type
    count: int

    def dump(self, addr: int, fmt: str = "") -> str:
        ret = []
        for _ in range(self.count):
            ret.append(self.inner.dump(addr, fmt))
            addr += self.inner.size()
        return f"[{', '.join(ret)}]"

    def size(self) -> int:
        return self.inner.size() * self.count

    def __str__(self) -> str:
        return f"[{self.count}]{self.inner}"


@dataclass
class MapType(Type):
    """
    A map type in Go, notated as map[key]val.

    Note that maps in Go are actually pointers to the inner map,
    but the map type printer here directly prints the inner map.

    Maps don't have a simple layout, and may reasonably change,
    but the last change was in 2017, so it probably won't.

    The layout assumed is as follows (taken from src/runtime/map.go commit 1b4f1dc):

    type hmap struct {
        count      int
        flags      uint8
        B          uint8
        noverflow  uint16
        hash0      uint32
        buckets    unsafe.Pointer
        oldbuckets unsafe.Pointer
        nevacuate  uintptr
        extra      *mapextra
    }
    """

    key: Type
    val: Type

    @staticmethod
    def field_offsets() -> Dict[str, int]:
        word = word_size()
        offsets = compute_named_offsets(
            [
                ("count", word, word),  # int
                ("flags", 1, 1),  # uint8
                ("B", 1, 1),  # uint8
                ("noverflow", 2, 2),  # uint16
                ("hash0", 4, 4),  # uint32
                ("buckets", word, word),  # unsafe.Pointer
                ("oldbuckets", word, word),  # unsafe.Pointer
                ("nevacuate", word, word),  # uintptr
                ("extra", word, word),  # *mapextra
            ]
        )
        return offsets

    def dump(self, addr: int, fmt: str = "") -> str:
        bucket_count = 8  # taken from src/internal/abi/map.go commit 1b4f1dc
        word = word_size()
        offsets = self.field_offsets()
        val = pwndbg.gdblib.memory.read(addr, offsets["$size"])
        load = lambda off, sz: load_uint(val[off : off + sz])
        num_buckets = 1 << load(offsets["B"], 1)
        bucket_base = load(offsets["buckets"], word)
        keysize = self.key.size()
        valsize = self.val.size()
        # technically need to worry about padding but every go arch has max alignment of 8 and bucket count is 8
        # so padding is never actually possible
        [tophash_start, keys_start, vals_start, overflow_start, bucket_size] = compute_offsets(
            [
                (bucket_count, 1),
                (keysize * bucket_count, 1),
                (valsize * bucket_count, 1),
                (word, word),
            ]
        )
        ret = []
        # TODO: deal with evacuated buckets
        for i in range(num_buckets):
            bucket_ptr = bucket_base + bucket_size * i
            while bucket_ptr:
                bucket = pwndbg.gdblib.memory.read(bucket_ptr, bucket_size)
                for j in range(bucket_count):
                    if bucket[tophash_start + j] > 1:  # !isEmpty(bucket.tophash[j])
                        k = self.key.dump(bucket_ptr + keys_start + j * keysize, fmt)
                        v = self.val.dump(bucket_ptr + vals_start + j * valsize, fmt)
                        ret.append(f"{k}: {v}")
                bucket_ptr = load_uint(bucket[overflow_start : overflow_start + word])

        return f"{{{', '.join(ret)}}}"

    def size(self) -> int:
        return self.field_offsets()["$size"]

    def __str__(self) -> str:
        return f"map[{self.key}]{self.val}"


@dataclass
class StructType(Type):
    """
    A struct type in Go, notated as struct(SIZE){FIELDS},
    where SIZE is the size of the struct in bytes,
    and FIELDS is a semicolon-separated list of OFFSET:NAME:TYPE fields.
    """

    fields: List[Tuple[str, Type | str, int]]
    sz: int
    name: str | None = None

    def dump(self, addr: int, fmt: str = "") -> str:
        vals = []
        for name, ty, off in self.fields:
            base = addr + off
            if isinstance(ty, str):
                vals.append((name, f"({ty}) at {base:#x}"))
            else:
                vals.append((name, ty.dump(base, fmt)))
        body = ", ".join(f"{name}: {val}" for (name, val) in vals)
        name = self.name or "struct"
        return f"{name} {{{body}}}"

    def size(self) -> int:
        return self.sz

    def __str__(self) -> str:
        body = ";".join(
            f"{off}:{name}:{ty}" for (name, ty, off) in self.fields if not isinstance(ty, str)
        )
        return f"struct({self.sz}){{{body}}}"


_ident_first = set(string.ascii_letters + "_")
_ident_rest = _ident_first | set(string.digits)


def _parse_posint(ty: str) -> Tuple[int, str] | None:
    if not ty or not ty[0].isdigit():
        return None
    for i in range(1, len(ty)):
        if not ty[i].isdigit():
            break
    else:
        i = len(ty)
    try:
        return (int(ty[:i]), ty[i:])
    except ValueError:
        return None


def _parse_ident(ty: str) -> Tuple[str, str] | None:
    if not ty or ty[0] not in _ident_first:
        return None
    for i in range(1, len(ty)):
        if ty[i] not in _ident_rest:
            break
    else:
        i = len(ty)
    return (ty[:i], ty[i:])


def _parse_basic_ty(ty: str) -> Tuple[BasicType, str] | None:
    parse = _parse_ident(ty)
    if not parse:
        return None
    (ident, rest) = parse
    try:
        return (BasicType(ident), rest)
    except ValueError:
        if rest:
            return None
        # only raise an exception if it's a full string parse
        # otherwise the exception message could be inaccurate
        raise


def _parse_slice_ty(ty: str) -> Tuple[SliceType, str] | None:
    if not ty.startswith("[]"):
        return None
    if (inner := _parse_type(ty[2:])) is None:
        return None
    return (SliceType(inner[0]), inner[1])


def _parse_pointer_ty(ty: str) -> Tuple[PointerType, str] | None:
    if not ty.startswith("*"):
        return None
    if (inner := _parse_type(ty[1:])) is None:
        return None
    return (PointerType(inner[0]), inner[1])


def _parse_array_ty(ty: str) -> Tuple[ArrayType, str] | None:
    if not ty.startswith("["):
        return None
    if (count := _parse_posint(ty[1:])) is None:
        return None
    if not count[1].startswith("]"):
        return None
    if (inner := _parse_type(count[1][1:])) is None:
        return None
    return (ArrayType(inner[0], count[0]), inner[1])


def _parse_map_ty(ty: str) -> Tuple[MapType, str] | None:
    if not ty.startswith("map["):
        return None
    if (key := _parse_type(ty[4:])) is None:
        return None
    if not key[1].startswith("]"):
        return None
    if (val := _parse_type(key[1][1:])) is None:
        return None
    return (MapType(key[0], val[0]), val[1])


def _parse_struct_ty(ty: str) -> Tuple[StructType, str] | None:
    if not ty.startswith("struct("):
        return None
    size_parse = _parse_posint(ty[7:])
    if size_parse is None:
        return None
    (size, cur) = size_parse
    if not cur.startswith("){"):
        return None
    cur = cur[2:]
    fields = []
    is_first = True
    while cur:
        if cur.startswith("}"):
            return (StructType(fields, size), cur[1:])
        if is_first:
            is_first = False
        elif not cur.startswith(";"):
            return None
        cur = cur.lstrip(";")
        offset_parse = _parse_posint(cur)
        if offset_parse is None:
            return None
        (field_offset, cur) = offset_parse
        if not cur.startswith(":"):
            return None
        name_parse = _parse_ident(cur[1:])
        if name_parse is None:
            return None
        (field_name, cur) = name_parse
        if not cur.startswith(":"):
            return None
        type_parse = _parse_type(cur[1:])
        if type_parse is None:
            return None
        (field_type, cur) = type_parse
        fields.append((field_name, field_type, field_offset))
    return None


def _parse_type(ty: str) -> Tuple[Type, str] | None:
    for f in [
        _parse_struct_ty,
        _parse_map_ty,
        _parse_array_ty,
        _parse_pointer_ty,
        _parse_slice_ty,
        _parse_basic_ty,
    ]:
        parse = f(ty)
        if parse is not None:
            return parse
    return None


def parse_type(ty: str) -> Type:
    ret = _parse_type(ty)
    if ret is None:
        raise ValueError(f"Type {ty} could not be parsed.")
    if ret[1]:
        raise ValueError(f"Type {ty} has trailing data.")
    return ret[0]
