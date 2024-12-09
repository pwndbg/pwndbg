from __future__ import annotations

import dataclasses
import json
import string
import struct
import textwrap
from abc import ABC
from abc import abstractmethod
from dataclasses import dataclass
from enum import IntEnum
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Literal
from typing import Set
from typing import Tuple
from typing import cast

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.color.memory
import pwndbg.hexdump
import pwndbg.lib.cache
from pwndbg.color import generateColorFunction
from pwndbg.color import message
from pwndbg.color import theme

line_width = pwndbg.config.add_param(
    "go-dump-line-width", 80, "the soft line width for go-dump pretty printing"
)
indent_amount = pwndbg.config.add_param(
    "go-dump-indent-amount", 4, "the indent amount for go-dump pretty printing"
)

debug_color = theme.add_color_param(
    "go-dump-debug", "blue", "color for 'go-dump' command's debug info when --debug is specified"
)


@pwndbg.lib.cache.cache_until("start", "stop", "objfile")
def word_size() -> int:
    """
    Gets the Go word size for the current architecture.

    Values taken from https://github.com/golang/go/blob/20b79fd5775c39061d949569743912ad5e58b0e7/src/go/types/sizes.go#L233-L252
    """
    return {"i386": 4, "x86-64": 8, "aarch64": 8, "arm": 4, "rv64": 8, "powerpc": 8, "sparc": 8}[
        pwndbg.aglib.arch.name
    ]


def _align(offset: int, n: int) -> int:
    ret = offset + n - 1
    return ret - ret % n


def compute_offsets(fields: Iterable[Tuple[int, int]]) -> List[int]:
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


def compute_named_offsets(fields: Iterable[Tuple[str, int, int]]) -> Dict[str, int]:
    """
    Like compute_offsets, but takes in field names and returns a dictionary
    mapping field name to offset instead.

    Also maps in a special $size field with the size of the struct.
    """
    offsets = compute_offsets([f[1:] for f in fields])
    ret = dict(zip([f[0] for f in fields] + ["$size"], offsets))
    return ret


def _indent(s: str) -> str:
    return textwrap.indent(s, " " * int(indent_amount))


@dataclass(frozen=True)
class FormatOpts:
    int_hex: bool = False
    debug: bool = False
    pretty: bool = False
    float_decimals: int | None = None

    def fmt_int(self, val: int) -> str:
        if self.int_hex:
            return hex(val)
        else:
            return str(val)

    def fmt_float(self, val: float) -> str:
        if self.float_decimals is not None:
            return format(val, f".{self.float_decimals}f")
        else:
            return str(val)

    def fmt_str(self, val: str) -> str:
        return json.dumps(val)

    def fmt_bytes(self, val: bytes) -> str:
        try:
            return self.fmt_str(val.decode("utf8"))
        except UnicodeDecodeError:
            return repr(bytes(val))

    def fmt_debug(self, val: str, default: str = "") -> str:
        if self.debug:
            return generateColorFunction(debug_color)(val)
        else:
            return default

    def fmt_elems(self, elems: Iterable[str]) -> str:
        if not self.pretty:
            return ", ".join(elems)
        # store elems in a list to not consume the iterable
        elems = list(elems)
        joined = ", ".join(elems)
        if len(joined) <= int(line_width):
            return joined
        joined = ",\n".join(elems)
        return f"\n{_indent(joined)}\n"

    def fmt_ptr(self, val: int) -> str:
        return pwndbg.color.memory.get_address_and_symbol(val)


@dataclass
class Type(ABC):
    meta: GoTypeMeta | None

    @abstractmethod
    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        """Dump a type from memory given an address and format."""
        pass

    @abstractmethod
    def size(self) -> int:
        """
        Returns the size of a type in bytes.

        Used for computing array and struct layouts.
        """
        pass

    @abstractmethod
    def get_typename(self) -> str:
        """
        Returns the typename of a type. Should be reparsable via _parse_ty.

        Also used to get the string representation.
        """
        pass

    def is_cyclic(self) -> bool:
        """
        Checks if a type is cyclic (contains references to itself), e.g. type a []a
        """

        return _cyclic_helper(self, set())

    def additional_metadata(self) -> List[str]:
        """
        Returns a list of lines of additional metadata to dump from the `go-type` command.
        """
        return []

    def __str__(self) -> str:
        return self.get_typename()


def _cyclic_helper(val: Any, seen: Set[int]) -> bool:
    if isinstance(val, Type):
        k = id(val)
        if k in seen:
            return True
        seen.add(k)
        return any(_cyclic_helper(v, seen) for v in val.__dict__.values())
    elif isinstance(val, (list, tuple)):
        return any(_cyclic_helper(v, seen) for v in val)
    else:
        return False


def load_uint(data: bytes, endian: Literal["little", "big"] | None = None) -> int:
    return int.from_bytes(data, endian or pwndbg.aglib.arch.endian)


def load_int(data: bytes) -> int:
    n = load_uint(data)
    wrap = 1 << (len(data) * 8 - 1)
    if n >= wrap:
        n -= wrap * 2
    return n


def load_float(data: bytes) -> float:
    endian = ">" if pwndbg.aglib.arch.endian == "big" else "<"
    if len(data) == 4:
        return struct.unpack(endian + "f", data)[0]
    if len(data) == 8:
        return struct.unpack(endian + "d", data)[0]
    raise ValueError("Invalid float length")


# only warn with a given message once per execution
@pwndbg.lib.cache.cache_until("start")
def emit_warning(msg: str):
    print(message.warn(msg))


@pwndbg.lib.cache.cache_until("objfile")
def get_elf() -> pwndbg.aglib.elf.ELFInfo | None:
    try:
        return pwndbg.aglib.elf.get_elf_info_rebased(
            pwndbg.aglib.file.get_proc_exe_file(), pwndbg.aglib.proc.binary_base_addr
        )
    except OSError:
        return None


def read_buildversion(addr: int) -> str:
    """
    Reads a Go runtime.buildVersion string to extract the version.
    """
    word = word_size()
    version_ptr = load_uint(pwndbg.aglib.memory.read(addr, word))
    version_len = load_uint(pwndbg.aglib.memory.read(addr + word, word))
    return "" if version_len == 0 else pwndbg.aglib.memory.read(version_ptr, version_len).decode()


@pwndbg.lib.cache.cache_until("objfile")
def get_go_version() -> Tuple[int, ...] | None:
    """
    Try to determine the Go version used to compile the binary.

    None can be returned if the version couldn't be inferred,
    at which point it's probably best to assume latest version.
    """
    # if a runtime.buildVersion symbol exists, prefer that
    buildversion_addr = pwndbg.aglib.symbol.lookup_symbol_addr("runtime.buildVersion")
    if buildversion_addr is not None:
        version_string = read_buildversion(buildversion_addr)
    else:
        elf = get_elf()
        # could do a linear search through executable pages for "\xff Go buildinf:" as a fallback
        if elf is None:
            return None
        buildinfo = next(
            (cast(int, s["sh_addr"]) for s in elf.sections if s["x_name"] == ".go.buildinfo"), None
        )
        # again, could do linear search
        if buildinfo is None:
            return None
        # check for flags & flagsVersionInl
        if (pwndbg.aglib.memory.read(buildinfo + 15, 1)[0] & 2) != 2:
            buildversion_addr = load_uint(pwndbg.aglib.memory.read(buildinfo + 16, word_size()))
            version_string = read_buildversion(buildversion_addr)
        else:
            version_string = read_varint_str(buildinfo + 32).decode()
    if version_string == "unknown":
        return None
    if not version_string.startswith("go"):
        emit_warning(f"Go version string {version_string!r} doesn't start with 'go'")
        return None
    return tuple(int(x) for x in version_string[2:].split("."))


@pwndbg.lib.cache.cache_until("objfile")
def _get_moduledata_types() -> Tuple[Tuple[int, int], ...] | None:
    ret = []
    try:
        md = pwndbg.aglib.symbol.lookup_symbol("runtime.firstmoduledata")
        if md:
            while True:
                start = int(md["types"])
                end = int(md["etypes"])
                ret.append((start, end))
                if int(md["next"]):
                    md = md["next"].dereference()
                else:
                    return tuple(ret)
        else:
            emit_warning(
                "Warning: Could not find `runtime.firstmoduledata` symbol, so a heuristic is used instead"
            )
    except pwndbg.dbg_mod.Error as e:
        emit_warning(
            f"Warning: Exception '{e}' occurred while trying to parse `runtime.firstmoduledata`, so a heuristic is used instead"
        )
    return None


@pwndbg.lib.cache.cache_until("objfile")
def _guess_moduledata_types() -> int | None:
    # the type:* symbol can indicate type start
    type_start = pwndbg.aglib.symbol.lookup_symbol_addr("type:*")
    if type_start is not None:
        return type_start
    # otherwise, just assume that types are at the start of .rodata if there aren't any debug symbols
    # not a great workaround, but parsing moduledata manually is very version-dependent
    elf = get_elf()
    if elf is not None:
        addr = next(
            (cast(int, x["sh_addr"]) for x in elf.sections if x["x_name"] == ".rodata"), None
        )
        return addr
    return None


def get_type_start(addr: int | None = None) -> int | None:
    """
    Given the address to a type, try to find the moduledata types section containing it.

    Necessary to determine the base address that the type name is offset by.
    """
    # try to get type start by traversing moduledata symbol
    # will only work if debug symbols are enabled
    md_types = _get_moduledata_types()
    if md_types is not None:
        for start, end in md_types:
            if addr is None or start <= addr < end:
                return start
        emit_warning(
            f"Warning: Type at {addr:#x} is out of bounds of all module data, so a heuristic is used instead"
        )
        # if we found at least one moduledata, use the start of the first one
        if md_types:
            return md_types[0][0]
    return _guess_moduledata_types()


def read_varint_str(addr: int) -> bytes:
    """
    Read a length-prefix string encoded with Go's variable length encoding.

    Implementation taken from https://github.com/golang/go/blob/9d33956503c0d96c0c5666d374173f7ac9756d98/src/internal/abi/type.go#L640-L649
    """
    orig_addr = addr
    strlen = 0
    while True:
        b = pwndbg.aglib.memory.read(addr, 1)[0]
        strlen = (strlen << 7) | (b & 0x7F)
        if b == 0x80 or strlen > 0x1000:
            # we're probably not actually reading a varint str and should just return some bytes to avoid infinite looping
            return pwndbg.aglib.memory.read(orig_addr, 16)
        addr += 1
        if not (b & 0x80):
            break
    # pwndbg.aglib.memory.read doesn't support 0-length reads
    if strlen == 0:
        return b""
    return pwndbg.aglib.memory.read(addr, strlen)


def read_type_name(addr: int) -> bytes:
    """
    Reads a Go type name given the address to the name.

    Go type names are stored as a 1 byte bitfield followed by a varint length prefixed string after 1.17.

    Prior to 1.17, they were stored as a 1 byte bitfield followed by a 2 byte length prefixed string.
    """
    vers = get_go_version()
    if vers is not None and vers < (1, 17):
        # reverse the bytestring because Go uses big endian
        strlen = load_uint(pwndbg.aglib.memory.read(addr + 1, 2), "big")
        if strlen == 0:
            return b""
        return pwndbg.aglib.memory.read(addr + 3, strlen)
    return read_varint_str(addr + 1)


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
    addr: int
    size: int = 0
    align: int = 1
    direct_iface: bool = False


@dataclass
class BackrefType(Type):
    """
    A temporary placeholder type used when dumping recursive types, e.g. type a []a
    """

    key: int

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()):
        raise NotImplementedError(f"Cannot dump placeholder type {type(self).__name__}.")

    def size(self) -> int:
        raise NotImplementedError(
            f"Cannot get size of placeholder type {type(self).__name__}. Perhaps the type is ill-formed? (e.g. struct that contains itself without indirection)"
        )

    def get_typename(self) -> str:
        if self.meta:
            return f"runtime({self.meta.size}){self.meta.addr:#x}"
        else:
            return "..."


def decode_runtime_type(addr: int, keep_backrefs: bool = False) -> Tuple[GoTypeMeta, Type | None]:
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

    cache: Dict[int, Tuple[GoTypeMeta, Type | None]] = {}
    (meta, rec_ty) = _inner_decode_runtime_type(addr, cache)

    if not keep_backrefs:
        rec_ty = _remove_backrefs(rec_ty, cache)
    return (meta, rec_ty)


def _remove_backrefs(ty: Any, cache: Dict[int, Tuple[GoTypeMeta, Type | None]]) -> Any:
    """
    Helper function to replace all _BackrefType instances after the cache is fully resolved.

    May mutate the argument.
    """
    if isinstance(ty, BackrefType):
        return cache[ty.key][1]
    elif isinstance(ty, Type):
        d = ty.__dict__
        for k, v in d.items():
            d[k] = _remove_backrefs(v, cache)
        return ty
    elif isinstance(ty, (list, tuple)):
        constructor = type(ty)
        return constructor(_remove_backrefs(x, cache) for x in ty)
    else:
        return ty


def _inner_decode_runtime_type(
    addr: int, cache: Dict[int, Tuple[GoTypeMeta, Type | None]]
) -> Tuple[GoTypeMeta, Type | None]:
    """
    Internal function for decode_runtime_type with a cache to avoid recursive types.
    """

    if addr in cache:
        return cache[addr]
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
    load = lambda off, sz: load_uint(pwndbg.aglib.memory.read(addr + off, sz))
    type_start = get_type_start(addr)
    tflag = load(offsets["TFlag"], 1)
    if type_start is None:
        name = "unknown name"
    else:
        name_ptr = type_start + load(offsets["Str"], 4)
        bname = read_type_name(name_ptr)
        try:
            name = bname.decode()
        except UnicodeDecodeError:
            name = repr(bytes(bname))
    kind_raw = load(offsets["Kind_"], 1)
    # KindMask is set to (1 << 5) - 1
    try:
        kind = GoTypeKind(kind_raw & ((1 << 5) - 1))
    except ValueError:
        kind = GoTypeKind.INVALID
    if kind == GoTypeKind.INVALID:
        return (GoTypeMeta(f"invalid type `{name}` at {addr:#x}", kind, addr), None)
    # if TFlagExtraStar is set, remove the leading * from type name
    if (tflag & 2) and name.startswith("*"):
        name = name[1:]
    size = load(offsets["Size_"], word)
    align = load(offsets["Align_"], 1)
    meta = GoTypeMeta(
        name, kind, addr, size=size, align=align, direct_iface=(kind_raw & (1 << 5)) != 0
    )
    cache[addr] = (meta, BackrefType(meta, addr))
    simple_name = kind.get_simple_name()

    def compute() -> Tuple[GoTypeMeta, Type | None]:
        if simple_name is not None:
            return (meta, BasicType(meta, simple_name))
        elif kind == GoTypeKind.FUNC:
            in_count = load(offsets["$size"], 2)
            out_count = load(offsets["$size"] + 2, 2)
            vararg_bit = 1 << 15
            is_vararg = bool(out_count & vararg_bit)
            out_count &= ~vararg_bit
            # functions store stuff after the uncommon type
            if tflag & 1:
                uncommon_type_size = 16  # nameoff, uint16, uint16, uint32, uint32
            else:
                uncommon_type_size = 0
            func_type_size = offsets["$size"] + 4
            # account for alignment when word size > 4
            if func_type_size % word != 0:
                func_type_size += word - func_type_size % word
            func_type_size += uncommon_type_size
            info = []
            for i in range(in_count + out_count):
                ty_ptr = load(func_type_size + i * word, word)
                (ty_meta, _) = _inner_decode_runtime_type(ty_ptr, cache)
                if i < in_count:
                    if is_vararg and i == in_count - 1:
                        suffix = "..."
                    else:
                        suffix = ""
                    info.append(f"Argument {i}{suffix}:")
                else:
                    info.append(f"Return value {i - in_count}:")
                info += [f"    Type name: {ty_meta.name}", f"    Type addr: {ty_ptr:#x}"]
            return (meta, BasicType(meta, "funcptr", info))
        elif kind == GoTypeKind.ARRAY:
            elem_ty_ptr = load(offsets["$size"], word)
            arr_len = load(offsets["$size"] + word * 2, word)
            elem_meta, elem_ty = _inner_decode_runtime_type(elem_ty_ptr, cache)
            # reserialize name to fix inconsistencies
            meta.name = f"[{arr_len}]{elem_meta.name}"
            return (meta, elem_ty and ArrayType(meta, elem_ty, arr_len))
        elif kind == GoTypeKind.INTERFACE:
            methods_count = load(offsets["$size"] + word * 2, word)
            if methods_count == 0:
                return (meta, BasicType(meta, "any"))
            elif type_start is None:
                return (meta, BasicType(meta, "interface", [f"Method count: {methods_count}"]))
            else:
                info = []
                methods_ptr = load(offsets["$size"] + word, word)
                for i in range(methods_count):
                    base = methods_ptr + i * 8
                    meth_name_off = load_uint(pwndbg.aglib.memory.read(base, 4))
                    inner_off = load_uint(pwndbg.aglib.memory.read(base + 4, 4))
                    bmeth_name = read_type_name(type_start + meth_name_off)
                    inner_ty_ptr = type_start + inner_off
                    (inner_meta, _) = _inner_decode_runtime_type(inner_ty_ptr, cache)
                    try:
                        meth_name = bmeth_name.decode()
                    except UnicodeDecodeError:
                        meth_name = repr(bytes(bmeth_name))
                    info += [
                        f"Method {meth_name}:",
                        f"    Type name: {inner_meta.name}",
                        f"    Type addr: {inner_ty_ptr:#x}",
                    ]
                return (meta, BasicType(meta, "interface", info))
        elif kind == GoTypeKind.MAP:
            key_ty_ptr = load(offsets["$size"], word)
            val_ty_ptr = load(offsets["$size"] + word, word)
            key_meta, key_ty = _inner_decode_runtime_type(key_ty_ptr, cache)
            if key_ty is None:
                return (meta, None)
            val_meta, val_ty = _inner_decode_runtime_type(val_ty_ptr, cache)
            if val_ty is None:
                return (meta, None)
            # reserialize name to fix inconsistencies
            meta.name = f"map[{key_meta.name}]{val_meta.name}"
            # Go maps are actually pointers, but the map here is not
            return (meta, PointerType(meta, MapType(meta, key_ty, val_ty)))
        elif kind == GoTypeKind.POINTER:
            elem_ty_ptr = load(offsets["$size"], word)
            elem_meta, elem_ty = _inner_decode_runtime_type(elem_ty_ptr, cache)
            # reserialize name to fix inconsistencies
            meta.name = f"*{elem_meta.name}"
            return (meta, elem_ty and PointerType(meta, elem_ty))
        elif kind == GoTypeKind.SLICE:
            elem_ty_ptr = load(offsets["$size"], word)
            elem_meta, elem_ty = _inner_decode_runtime_type(elem_ty_ptr, cache)
            # reserialize name to fix inconsistencies
            meta.name = f"[]{elem_meta.name}"
            return (meta, elem_ty and SliceType(meta, elem_ty))
        elif kind == GoTypeKind.STRUCT:
            fields_ptr = load(offsets["$size"] + word, word)
            fields_count = load(offsets["$size"] + word * 2, word)
            fields: List[Tuple[str, Type | str, int]] = []
            vers = get_go_version()
            if vers is not None and vers < (1, 19):
                offset_shift = 1
            else:
                offset_shift = 0
            for i in range(fields_count):
                base = fields_ptr + i * word * 3
                bfield_name = read_type_name(load_uint(pwndbg.aglib.memory.read(base, word)))
                try:
                    field_name = bfield_name.decode()
                except UnicodeDecodeError:
                    field_name = repr(bytes(bfield_name))
                field_ty_ptr = load_uint(pwndbg.aglib.memory.read(base + word, word))
                field_off = (
                    load_uint(pwndbg.aglib.memory.read(base + word * 2, word)) >> offset_shift
                )
                (field_meta, field_ty) = _inner_decode_runtime_type(field_ty_ptr, cache)
                if field_ty is None:
                    field_ty = field_meta.name
                fields.append((field_name, field_ty, field_off))
            fields.sort(key=lambda f: f[2])
            sz = load(offsets["Size_"], word)
            return (
                meta,
                StructType(meta, fields, sz, None if name.startswith("struct ") else name),
            )
        else:
            # currently channels and functions are unsupported
            return (meta, None)

    ret = compute()
    if not isinstance(ret[1], BackrefType):
        cache[addr] = ret
    return ret


@dataclass
class BasicType(Type):
    """
    A primitive Go type.

    Complex numbers are laid out as a real and imaginary part (both floats).
    Strings are laid out as a pointer and a length.

    Methodless interfaces (the interface{} type) are denoted as any,
    and interfaces with methods are denoted as interface.

    Function pointers are denoted as funcptr.
    """

    name: str
    sz: int = dataclasses.field(init=False)
    extra_meta: List[str] = dataclasses.field(default_factory=list)

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        val = pwndbg.aglib.memory.read(addr, self.size())
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
                ty_ptr = load_uint(pwndbg.aglib.memory.read(iface_ptr + word, word))
            else:
                ty_ptr = load_uint(val[:word])
            if ty_ptr == 0:
                return "nil"
            meta, parsed_inner = decode_runtime_type(ty_ptr)
            data_ptr = addr + word
            if not meta.direct_iface:
                data_ptr = load_uint(pwndbg.aglib.memory.read(data_ptr, word))
            prefix = fmt.fmt_debug(f"(ty @ {ty_ptr:#x}, data @ {data_ptr:#x}) ")
            if data_ptr == 0:
                return f"{prefix}({meta.name}) nil"
            if parsed_inner is not None:
                dump = parsed_inner.dump(data_ptr, fmt)
                return f"{prefix}({meta.name}) {dump}"
            return f"{prefix}({meta.name}) @ {data_ptr:#x}"
        if ty == "bool":
            return "true" if val != b"\x00" else "false"
        if ty == "funcptr":
            word = word_size()
            closure_addr = load_uint(val)
            f = load_uint(pwndbg.aglib.memory.read(closure_addr, word))
            return fmt.fmt_debug(f"(closure @ {closure_addr}) ") + fmt.fmt_ptr(f)
        if ty.startswith("int") or ty.startswith("uint"):
            if ty.startswith("int"):
                n = load_int(val)
            else:
                n = load_uint(val)
            if ty.endswith("ptr"):
                return fmt.fmt_ptr(n)
            return fmt.fmt_int(n)
        if ty.startswith("float"):
            return fmt.fmt_float(load_float(val))
        if ty.startswith("complex"):
            word = len(val) // 2
            real = fmt.fmt_float(load_float(val[:word]))
            im_val = load_float(val[word:])
            sign = "+"
            if im_val < 0:
                sign = "-"
                im_val = -im_val
            im = fmt.fmt_float(im_val)
            return f"({real} {sign} {im}i)"
        if ty == "string":
            word = word_size()
            ptr = load_uint(val[:word])
            strlen = load_uint(val[word:])
            # pwndbg.aglib.memory.read doesn't support 0-length reads
            if strlen == 0:
                data = b""
            else:
                data = pwndbg.aglib.memory.read(ptr, strlen)
            return fmt.fmt_debug(f"(str @ {ptr:#x}, len = {strlen}) ") + fmt.fmt_bytes(data)
        raise ValueError(f"Could not dump type {ty}.")

    def size(self) -> int:
        return self.sz

    def get_typename(self) -> str:
        return self.name

    def additional_metadata(self) -> List[str]:
        return self.extra_meta

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
        elif ty in ("int", "uint", "uintptr", "funcptr"):
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

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        word = word_size()
        val = pwndbg.aglib.memory.read(addr, word * 3)
        ptr = load_uint(val[:word])
        slice_len = load_uint(val[word : word * 2])
        ret = []
        for _ in range(slice_len):
            ret.append(fmt.fmt_debug(f"(elem @ {ptr:#x}) ") + self.inner.dump(ptr, fmt))
            ptr += self.inner.size()
        prefix = ""
        if fmt.debug:
            cap = load_uint(val[word * 2 :])
            prefix = fmt.fmt_debug(f"(cap = {cap}) ")
        return f"{prefix}[{fmt.fmt_elems(ret)}]"

    def size(self) -> int:
        return word_size() * 3

    def get_typename(self) -> str:
        return f"[]{self.inner}"

    def additional_metadata(self) -> List[str]:
        if self.inner.meta:
            return [
                f"Elem type name: {self.inner.meta.name}",
                f"Elem type addr: {self.inner.meta.addr:#x}",
            ]
        return []


@dataclass
class PointerType(Type):
    """
    A pointer type in Go, notated as *inner.
    """

    inner: Type

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        word = word_size()
        ptr = load_uint(pwndbg.aglib.memory.read(addr, word))
        if ptr == 0:
            return "nil"
        inner = self.inner.dump(ptr, fmt)
        prefix = fmt.fmt_debug(f"(val @ {ptr:#x}) ")
        return f"{prefix}&{inner}"

    def size(self) -> int:
        return word_size()

    def get_typename(self) -> str:
        return f"*{self.inner}"

    def additional_metadata(self) -> List[str]:
        # maps are returned as pointers to map in a parser
        # so show map metadata through the pointer metadata
        if isinstance(self.inner, MapType):
            info = self.inner.additional_metadata()
            if info:
                return info
        if self.inner.meta:
            return [
                f"Pointee type name: {self.inner.meta.name}",
                f"Pointee type addr: {self.inner.meta.addr:#x}",
            ]
        return []


@dataclass
class ArrayType(Type):
    """
    An array type in Go, notated as [count]inner.

    Arrays are laid out as contiguous data.
    """

    inner: Type
    count: int

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        ret = []
        for _ in range(self.count):
            ret.append(fmt.fmt_debug(f"(elem @ {addr:#x}) ") + self.inner.dump(addr, fmt))
            addr += self.inner.size()
        return f"[{fmt.fmt_elems(ret)}]"

    def size(self) -> int:
        return self.inner.size() * self.count

    def get_typename(self) -> str:
        return f"[{self.count}]{self.inner}"

    def additional_metadata(self) -> List[str]:
        if self.inner.meta:
            return [
                f"        Length: {self.count}",
                f"Elem type name: {self.inner.meta.name}",
                f"Elem type addr: {self.inner.meta.addr:#x}",
            ]
        return []


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

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        bucket_count = 8  # taken from src/internal/abi/map.go commit 1b4f1dc
        word = word_size()
        offsets = self.field_offsets()
        val = pwndbg.aglib.memory.read(addr, offsets["$size"])
        load = lambda off, sz: load_uint(val[off : off + sz])
        num_buckets = 1 << load(offsets["B"], 1)
        num_oldbuckets = num_buckets >> 1
        oldbucket_base = load(offsets["oldbuckets"], word)
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
        for i in range(num_buckets):
            bucket_ptr = bucket_base + bucket_size * i
            if oldbucket_base and i < num_oldbuckets:
                oldbucket_ptr = oldbucket_base + bucket_size * i
                oldbucket = pwndbg.aglib.memory.read(oldbucket_ptr, bucket_size)
                if not (1 < oldbucket[tophash_start] < 5):  # !evacuated(bucket)
                    bucket_ptr = oldbucket_ptr
            while bucket_ptr:
                bucket = pwndbg.aglib.memory.read(bucket_ptr, bucket_size)
                for j in range(bucket_count):
                    if bucket[tophash_start + j] > 1:  # !isEmpty(bucket.tophash[j])
                        key_ptr = bucket_ptr + keys_start + j * keysize
                        val_ptr = bucket_ptr + vals_start + j * valsize
                        k = self.key.dump(key_ptr, fmt)
                        v = self.val.dump(val_ptr, fmt)
                        ret.append((key_ptr, val_ptr, k, v))
                bucket_ptr = load_uint(bucket[overflow_start : overflow_start + word])
        # sort map by key, using integer comparison if possible
        try:
            ret.sort(key=lambda t: int(t[2], 0))
        except ValueError:
            ret.sort(key=lambda t: t[2])
        formatted = []
        for kp, vp, k, v in ret:
            prefix = fmt.fmt_debug(f"(key @ {kp:#x}, val @ {vp:#x}) ")
            formatted.append(f"{prefix}{k}: {v}")
        return f"{{{fmt.fmt_elems(formatted)}}}"

    def size(self) -> int:
        return self.field_offsets()["$size"]

    def get_typename(self) -> str:
        return f"map[{self.key}]{self.val}"

    def additional_metadata(self) -> List[str]:
        ret = []
        if self.key.meta:
            ret += [
                f"Key type name: {self.key.meta.name}",
                f"Key type addr: {self.key.meta.addr:#x}",
            ]
        if self.val.meta:
            ret += [
                f"Val type name: {self.val.meta.name}",
                f"Val type addr: {self.val.meta.addr:#x}",
            ]
        return ret


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

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        vals = []
        for name, ty, off in self.fields:
            base = addr + off
            if isinstance(ty, str):
                vals.append((name, f"({ty}) @ {base:#x}"))
            else:
                vals.append((fmt.fmt_debug(f"(field @ {base:#x}) ") + name, ty.dump(base, fmt)))
        body = fmt.fmt_elems(f"{name}: {val}" for (name, val) in vals)
        name = self.name or "struct"
        return f"{name} {{{body}}}"

    def size(self) -> int:
        return self.sz

    def get_typename(self) -> str:
        body = ";".join(
            f"{off}:{name}:{ty}" for (name, ty, off) in self.fields if not isinstance(ty, str)
        )
        return f"struct({self.sz}){{{body}}}"

    def additional_metadata(self) -> List[str]:
        ret = []
        for name, ty, off in self.fields:
            if isinstance(ty, str) or not ty.meta:
                ret += [f"Field {name}:", f"    Offset: {off} ({off:#x})", f"    Type: {ty}"]
            else:
                ret += [
                    f"Field {name}:",
                    f"    Offset: {off} ({off:#x})",
                    f"    Type name: {ty.meta.name}",
                    f"    Type addr: {ty.meta.addr:#x}",
                ]
        return ret


@dataclass
class RuntimeType(Type):
    """
    A value of a runtime reflection type in Go, notated as runtime(SIZE)ADDRESS,
    where SIZE is the size of the type's value in bytes,
    and ADDRESS is the address of the type.

    This type is useful for serializing cyclic types.
    """

    sz: int
    addr: int

    def dump(self, addr: int, fmt: FormatOpts = FormatOpts()) -> str:
        (meta, ty) = decode_runtime_type(self.addr)
        if ty is not None:
            return f"({meta.name}) {ty.dump(addr, fmt)}"
        else:
            return f"[error resolving type `{meta.name}` at {addr:#x}]"

    def size(self) -> int:
        return self.sz

    def get_typename(self) -> str:
        return f"runtime({self.sz}){self.addr:#x}"


_ident_first = set(string.ascii_letters + "_")
_ident_rest = _ident_first | set(string.digits)

# x is included for parsing purposes
hex_digits = set("0123456789abcdefABCDEFxX")


def _parse_posint(ty: str) -> Tuple[int, str] | None:
    if not ty or ty[0] not in hex_digits:
        return None
    for i in range(1, len(ty)):
        if ty[i] not in hex_digits:
            break
    else:
        i = len(ty)
    try:
        return (int(ty[:i], 0), ty[i:])
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
        return (BasicType(None, ident), rest)
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
    return (SliceType(None, inner[0]), inner[1])


def _parse_pointer_ty(ty: str) -> Tuple[PointerType, str] | None:
    if not ty.startswith("*"):
        return None
    if (inner := _parse_type(ty[1:])) is None:
        return None
    return (PointerType(None, inner[0]), inner[1])


def _parse_array_ty(ty: str) -> Tuple[ArrayType, str] | None:
    if not ty.startswith("["):
        return None
    if (count := _parse_posint(ty[1:])) is None:
        return None
    if not count[1].startswith("]"):
        return None
    if (inner := _parse_type(count[1][1:])) is None:
        return None
    return (ArrayType(None, inner[0], count[0]), inner[1])


def _parse_map_ty(ty: str) -> Tuple[MapType, str] | None:
    if not ty.startswith("map["):
        return None
    if (key := _parse_type(ty[4:])) is None:
        return None
    if not key[1].startswith("]"):
        return None
    if (val := _parse_type(key[1][1:])) is None:
        return None
    return (MapType(None, key[0], val[0]), val[1])


def _parse_struct_ty(ty: str) -> Tuple[StructType, str] | None:
    if not ty.startswith("struct("):
        return None
    if (size_parse := _parse_posint(ty[7:])) is None:
        return None
    (size, cur) = size_parse
    if not cur.startswith("){"):
        return None
    cur = cur[2:]
    fields: List[Tuple[str, Type | str, int]] = []
    is_first = True
    while cur:
        if cur.startswith("}"):
            return (StructType(None, fields, size), cur[1:])
        if is_first:
            is_first = False
        elif not cur.startswith(";"):
            return None
        cur = cur.lstrip(";")
        if (offset_parse := _parse_posint(cur)) is None:
            return None
        (field_offset, cur) = offset_parse
        if not cur.startswith(":"):
            return None
        if (name_parse := _parse_ident(cur[1:])) is None:
            return None
        (field_name, cur) = name_parse
        if not cur.startswith(":"):
            return None
        if (type_parse := _parse_type(cur[1:])) is None:
            return None
        (field_type, cur) = type_parse
        fields.append((field_name, field_type, field_offset))
    return None


def _parse_runtime_ty(ty: str) -> Tuple[RuntimeType, str] | None:
    if not ty.startswith("runtime("):
        return None
    if (size_parse := _parse_posint(ty[8:])) is None:
        return None
    (size, rest) = size_parse
    if not rest.startswith(")"):
        return None
    if (addr_parse := _parse_posint(rest[1:])) is None:
        return None
    (addr, rest) = addr_parse
    return (RuntimeType(None, size, addr), rest)


def _parse_type(ty: str) -> Tuple[Type, str] | None:
    for f in [
        _parse_runtime_ty,
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
