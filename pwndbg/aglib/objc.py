"""
Apple Objective-C Runtime Support

This module implements support for analyzing the Apple Objective-C runtime. As
expected, Apple provides no oficial specification for the internal ABI of ObjC
and no guarantees of its stability, and so this module is not guaranteed to
work on all versions of Darwin.
"""

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Generator
from typing import Generic
from typing import TypeVar

from typing_extensions import override

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.macho
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.config
import pwndbg.lib.functions
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.dbg_mod import Type

T = TypeVar("T")


class _IdRaw:
    """
    Pointer to an Objective-C object in the heap.
    """

    def __init__(self, ptr: int):
        self.addr = ptr


class _IdTagged:
    """
    Tagged pointer to an Objective-C object.

    This is a bit of a misnomer, as tagged pointers may not be pointers at all,
    and the data for the entire object may be contained in the payload, with no
    backing allocation in the heap. It is up to the class to determine how to
    decode the payload properly.
    """

    def __init__(self, tag: int, payload: int, extended: bool):
        self.tag = tag
        self.payload = payload
        self.extended = extended

    def lookup_class(self) -> Class:
        """
        Looks up the class object matching the tag in this pointer.
        """
        classes = _tagged_pointer_classes()

        if self.extended:
            classes += self.tag - 256
        else:
            classes += self.tag

        ptr = pwndbg.aglib.memory.read_pointer_width(int(classes.address))
        ptr = _ptrauth_strip(ptr)

        return Class(ptr)


class _IsaPtr:
    """
    Pointer to an `isa_t` structure.
    """

    ISA_MASK = 0x0000000FFFFFFFF8
    "Mask of bits containing just the authenticated class pointer."

    def __init__(self, addr: int):
        self._addr = addr

    def _read(self) -> int:
        """
        Read the bits of the `isa_t` structure into an integer.
        """
        return pwndbg.aglib.memory.read_pointer_width(self._addr)

    def get_class(self) -> Class:
        ptr = self._read() & _IsaPtr.ISA_MASK
        ptr = _ptrauth_strip(ptr)

        return Class(ptr)


def _isa_class_mask() -> int:
    return pwndbg.aglib.memory.read_pointer_width(
        pwndbg.aglib.symbol.lookup_symbol_addr("objc_debug_isa_class_mask")
    )


class _ClassRoPtr:
    RO_META = 0x1
    RO_ROOT = 0x2
    RO_HAS_CXX_STRUCTORS = 0x4
    RO_HIDDEN = 0x10
    RO_EXCEPTION = 0x20
    RO_HAS_SWIFT_INITIALIZER = 0x40
    RO_IS_ARC = 0x80
    RO_HAS_CXX_DTOR_ONLY = 0x100
    RO_HAS_WEAK_WITHOUT_ARC = 0x200
    RO_FORBIDS_ASSOCIATED_OBJECTS = 0x400
    RO_FROM_BUNDLE = 0x20000000
    RO_FUTURE = 0x40000000
    RO_REALIZED = 0x80000000

    def __init__(self, addr: int):
        self._ptr = addr

    def name(self) -> bytes:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 24)
        return pwndbg.aglib.memory.string(ptr)

    def flags(self) -> int:
        return pwndbg.aglib.memory.u32(self._ptr)

    def methods(self) -> Generator[Method]:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 32)

        if ptr & 1 == 0:
            if ptr == 0:
                return
            yield from _MethodList(ptr).entries()
        else:
            if ptr & ~1 == 0:
                # Not expected to happen, but better safe than sorry.
                return

            list_of_lists = _RelativeListOfLists(_MethodList, ptr & ~1)
            for lst in list_of_lists.entries():
                if lst is None:
                    continue
                yield from lst.get_list().entries()

    def ivars(self) -> Generator[InstanceVariable]:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 0x30)
        if ptr != 0:
            yield from _IVarList(ptr).entries()

    def properties(self) -> Generator[ClassProperty]:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 0x40)
        if ptr & 1 == 0:
            if ptr == 0:
                return

            yield from _ClassPropertyList(ptr).entries()
        else:
            if ptr & ~1 == 0:
                # Not expected to happen, but better safe than sorry.
                return

            list_of_lists = _RelativeListOfLists(_ClassPropertyList, ptr & ~1)
            for lst in list_of_lists.entries():
                if lst is None:
                    continue
                yield from lst.get_list().entries()


class _ClassRwExtPtr:
    def __init__(self, ptr: int):
        self._ptr = ptr

    def ro(self) -> _ClassRoPtr:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr)
        ptr = _ptrauth_strip(ptr)
        return _ClassRoPtr(ptr)

    def methods(self) -> _ListArray[Method]:
        return _ListArray(_MethodList, self._ptr + pwndbg.aglib.typeinfo.ptrsize)

    def properties(self) -> _ListArray[ClassProperty]:
        return _ListArray(_ClassPropertyList, self._ptr + 2 * pwndbg.aglib.typeinfo.ptrsize)

    def demangled_name(self) -> bytes | None:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 4 * pwndbg.aglib.typeinfo.ptrsize)
        if ptr == 0:
            return None
        return pwndbg.aglib.memory.string(ptr)

    def version(self) -> int:
        return pwndbg.aglib.memory.u32(self._ptr + 5 * pwndbg.aglib.typeinfo.ptrsize)


class _ClassRwPtr:
    RW_REALIZED = 1 << 31

    def __init__(self, ptr: int):
        self._ptr = ptr

    def ro_or_rw_ext(self) -> _ClassRoPtr | _ClassRwExtPtr:
        ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr + 8)
        if ptr & 1 == 1:
            return _ClassRwExtPtr(ptr & ~1)
        return _ClassRoPtr(ptr)


class _ClassDataBitsPtr:
    """
    Pointer to a `class_data_bits_t` structure.
    """

    FAST_IS_RW_POINTER = 0x8000000000000000
    FAST_IS_SWIFT_LEGACY = 0x1
    FAST_IS_SWIFT_STABLE = 0x2
    FAST_HAS_DEFAULT_RR = 0x4

    FAST_DATA_MASK = 0x0F007FFFFFFFFFF8

    def __init__(self, ptr: int):
        self._ptr = ptr

    def data(self) -> _ClassRoPtr | _ClassRwPtr:
        if self._is_rw():
            return _ClassRwPtr(self._data_addr())

        return _ClassRoPtr(self._data_addr())

    def _is_rw(self) -> bool:
        return ((self._ptr & _ClassDataBitsPtr.FAST_IS_RW_POINTER) != 0) or (
            (self._flags() & _ClassRwPtr.RW_REALIZED) != 0
        )

    def _data_addr(self) -> int:
        return _ptrauth_strip(self._ptr) & _ClassDataBitsPtr.FAST_DATA_MASK

    def _flags(self) -> int:
        return pwndbg.aglib.memory.u32(self._data_addr())


class _EntList(Generic[T]):
    """
    Entity list.
    """

    _flags_mask: int = 0
    "Mask for the flag bits of `entsizeAndFlags`"

    def __init__(self, ptr: int):
        self._addr = self._addr_from_ptr(ptr)
        self._ptr = ptr

    def _entsize_and_flags(self) -> int:
        return pwndbg.aglib.memory.u32(self._addr)

    def _entries(self) -> int:
        return pwndbg.aglib.memory.u32(self._addr + 4)

    def flags(self) -> int:
        return self._entsize_and_flags() & self._flags_mask

    def entsize(self) -> int:
        return self._entsize_and_flags() & ~self._flags_mask

    def _modify_pointer(self, ptr: int) -> int:
        return ptr

    def _from_ptr(self, ptr: int) -> T:
        """
        Build the type of this list from a pointer.

        Must be implemented by the specialized class.
        """
        raise NotImplementedError()

    def _addr_from_ptr(self, ptr: int) -> int:
        """
        Strip any metadata from the pointer to this list.

        Must be implemented by the specialized class.
        """
        raise NotImplementedError()

    def __len__(self) -> int:
        return self._entries()

    def get(self, i: int) -> T:
        if i >= len(self):
            raise IndexError(f"Index {i} is out-of-range for entlist with {len(self)} entries")

        return self._from_ptr(self._modify_pointer(self._addr + 8 + i * self.entsize()))

    def entries(self) -> Generator[T]:
        for i in range(len(self)):
            yield self.get(i)


class _RelativeListOfListsEntry(Generic[T]):
    def __init__(self, ty: Callable[[int], _EntList[T]], ptr: int):
        self._ptr = ptr
        self._ty = ty

    def image_index(self) -> int:
        return pwndbg.aglib.memory.u64(self._ptr) & 0xFFFF

    def _list_offset(self) -> int:
        return pwndbg.aglib.memory.s64(self._ptr) >> 16

    def get_list(self) -> _EntList[T]:
        return self._ty(self._ptr + self._list_offset())


class _RelativeListOfLists(
    _EntList[_RelativeListOfListsEntry[T] | None],
    Generic[T],
):
    """
    An array of relative pointers to lists.

    This corresponds to the `relative_list_list_t` type in libobjc.
    """

    def __init__(self, ty: Callable[[int], _EntList[T]], ptr: int):
        super().__init__(ptr)
        self._ty = ty

    @override
    def _addr_from_ptr(self, ptr: int) -> int:
        # Top-Byte-Ignore is assumed for method lists, but method list pointers
        # may have metadata attached to them.
        return ptr & ~0xFF00000000000000

    @override
    def _from_ptr(self, ptr: int) -> _RelativeListOfListsEntry[T] | None:
        entry = _RelativeListOfListsEntry(self._ty, ptr)
        if not _header_info_rw_is_image_loaded(entry.image_index()):
            # The entry is only valid if its corresponding image has been marked
            # as loaded in `objc_debug_headerInfoRWs`.
            return None

        return entry


class _ListArray(Generic[T]):
    """
    A runtime-polymorphic array type for lists. May be a pointer to a list type,
    an array of pointers, or a _RelativeListOfLists, distinguished by a tag in
    a pointer.

    Strangely for Apple, the tagged pointer to the final list is contained
    inside the list array structure, rather than having the whole structure be
    inlined into a pointer value. Suspiciously sane.

    This corresponds to the `list_array_tt` type in libobjc.
    """

    def __init__(self, ty: Callable[[int], _EntList[T]], ptr: int):
        self._ptr = ptr
        self._ty = ty

    def entries(self) -> Generator[T]:
        raw_ptr = pwndbg.aglib.memory.read_pointer_width(self._ptr)

        tag = raw_ptr & 3
        ptr = raw_ptr & ~3

        if ptr == 0:
            return

        if tag == 0:
            # This is just a pointer to the list.
            yield from self._ty(ptr).entries()
        elif tag == 1:
            # This is an array of lists.
            count = pwndbg.aglib.memory.u32(ptr)
            for i in range(count):
                yield from self._ty(
                    pwndbg.aglib.memory.read_pointer_width(
                        ptr + 8 + i * pwndbg.aglib.typeinfo.ptrsize
                    )
                ).entries()
        elif tag == 2:
            # This is a relative list of lists.
            for ll in _RelativeListOfLists(self._ty, ptr).entries():
                yield from ll.get_list().entries()


def _header_info_rw_is_image_loaded(index: int) -> bool:
    """
    Queries `objc_debug_headerInfoRWs` and checks whether the image with the
    given index is loaded.
    """
    addr = pwndbg.aglib.memory.read_pointer_width(
        pwndbg.aglib.symbol.lookup_symbol_addr("objc_debug_headerInfoRWs")
    )

    count = pwndbg.aglib.memory.u32(addr)
    entsize = pwndbg.aglib.memory.u32(addr + 4)

    if index >= count:
        raise IndexError(
            f"Image index {index} is out-of-bounds for headerInfoRWs structure with {count} entries"
        )

    return pwndbg.aglib.memory.read_pointer_width(addr + 8 + entsize * index) & 1 == 1


def _tagged_pointer_classes() -> pwndbg.dbg_mod.Value:
    """
    The Objective-C runtime tagged pointer classs list.

    The classes to which the tag values in a tagged pointer corresponds are not
    fixed, and are instead stored in a runtime-global array that gets looked up
    when a message is sent.
    """
    return pwndbg.aglib.symbol.lookup_symbol("objc_debug_taggedpointer_classes").cast(
        pwndbg.aglib.typeinfo.void.pointer().pointer()
    )


def _ptr_obfuscation_value() -> int:
    """
    The Objective-C runtime obfuscates tagged pointer values.
    """
    return pwndbg.aglib.memory.read_pointer_width(
        pwndbg.aglib.symbol.lookup_symbol_addr("objc_debug_taggedpointer_obfuscator")
    )


def _try_decode_tagged_split(ptr: int) -> _IdTagged | None:
    """
    Decodes a tagged pointer encoded in the split-tag scheme, if it is tagged.

    This is the encoding scheme used in modern - iOS 14 and newer - ARM64
    platforms.

    If the pointer is not tagged, returns `None`.
    """
    if ptr & 0x8000000000000000 == 0:
        # Not a tagged pointer.
        return None

    if ptr & 7 == 7:
        # This is an extended tag with a 52-bit payload.
        tag = (ptr >> 55) & 0xFF
        payload = (ptr >> 3) & 0xFFFFFFFFFFFFF
        extended = True
    else:
        # This is a short tag with a 60-bit payload.
        tag = ptr & 7
        payload = (ptr >> 3) & 0xFFFFFFFFFFFFFFF
        extended = False

    return _IdTagged(tag, payload, extended)


def _try_decode_tagged_lsb(ptr: int) -> _IdTagged:
    """
    Decodes a tagged pointer encoded in the LSB-tag scheme, if it is tagged.

    This is the encoding scheme used in all x86-64 versions of Darwin.

    If the pointer is not tagged, returns `None`.
    """
    if ptr & 1 == 0:
        # Not a tagged pointer.
        return None

    if ptr & 14 == 14:
        # This is an extended tag with a 52-bit payload.
        tag = (ptr >> 4) & 0xFF
        payload = ptr >> 12
        extended = True
    else:
        # This is a short tage with a 60-bit payload.
        tag = (ptr >> 1) & 7
        payload = ptr >> 4
        extended = False

    return _IdTagged(tag, payload, extended)


def _decode_prog_id(ptr: int) -> _IdRaw | _IdTagged:
    """
    Given an Objective-C program, decode it.
    """

    # First, check for tagged pointers.
    tagged = None
    match pwndbg.aglib.arch.name:
        case "aarch64":
            tagged = _try_decode_tagged_split(ptr)
        case "x86-64":
            tagged = _try_decode_tagged_lsb(ptr)
        case other:
            raise AssertionError(f"Unexpected Objective-C architecture: {other}")
    if tagged is not None:
        # Successfuly decoded the tagged pointer.
        return tagged

    # This is a direct pointer.
    return _IdRaw(ptr)


def _ptrauth_strip(ptr: int) -> int:
    """
    Strip pointer signing information from a given signed pointer.
    """
    return ptr & 0xFFFFFFFFFFFF


class Object:
    _addr: int
    "Object pointer value, as seen in the program. May be tagged, obfuscated, authenticated."

    _id: _IdRaw | _IdTagged
    "Decoded object pointer value. May be tagged."

    def __init__(self, addr: int):
        self._addr = addr
        self._id = _decode_prog_id(addr)

    @property
    def cls(self) -> Class | None:
        if isinstance(self._id, _IdRaw):
            isa = _IsaPtr(self._id.addr)
            return isa.get_class()
        if isinstance(self._id, _IdTagged):
            return self._id.lookup_class()


class Class(Object):
    def __init__(self, addr: int):
        super().__init__(addr)
        assert isinstance(self._id, _IdRaw), "Class pointers are never tagged"

    def _data_bits(self) -> _ClassDataBitsPtr:
        # MyPy fails if we don't check this a second time.
        assert isinstance(self._id, _IdRaw), "Class pointers are never tagged"
        ptr = pwndbg.aglib.memory.read_pointer_width(self._id.addr + 32)
        ptr = _ptrauth_strip(ptr)
        return _ClassDataBitsPtr(ptr)

    def _ro(self) -> _ClassRoPtr:
        data = self._data_bits().data()
        if isinstance(data, _ClassRoPtr):
            return data
        if isinstance(data, _ClassRwPtr):
            ro_or_rw_ext = data.ro_or_rw_ext()
            if isinstance(ro_or_rw_ext, _ClassRwExtPtr):
                return ro_or_rw_ext.ro()
            if isinstance(ro_or_rw_ext, _ClassRoPtr):
                return ro_or_rw_ext
            # FIXME: Should be `typing.assert_never`, needs Python 3.11
            assert False
        else:
            # FIXME: Should be `typing.assert_never`, needs Python 3.11
            assert False

    def _rw_ext(self) -> _ClassRwExtPtr | None:
        data = self._data_bits().data()
        if isinstance(data, _ClassRoPtr):
            return None
        if isinstance(data, _ClassRwPtr):
            ro_or_rw_ext = data.ro_or_rw_ext()
            if isinstance(ro_or_rw_ext, _ClassRwExtPtr):
                return ro_or_rw_ext
            if isinstance(ro_or_rw_ext, _ClassRoPtr):
                return None
            # FIXME: Should be `typing.assert_never`, needs Python 3.11
            assert False
        else:
            # FIXME: Should be `typing.assert_never`, needs Python 3.11
            assert False

    @property
    def superclass(self) -> Class | None:
        # MyPy fails if we don't check this a second time.
        assert isinstance(self._id, _IdRaw), "Class pointers are never tagged"

        if self._ro().flags() & _ClassRoPtr.RO_ROOT != 0:
            # This is a root class, and thus has no superclass.
            return None

        ptr_addr = self._id.addr + pwndbg.aglib.typeinfo.ptrsize
        ptr = pwndbg.aglib.memory.read_pointer_width(ptr_addr)
        ptr = _ptrauth_strip(ptr)

        return Class(ptr)

    @property
    def name(self) -> bytes:
        return self._ro().name()

    @property
    def methods(self) -> Generator[Method]:
        if (rw_ext := self._rw_ext()) is not None:
            # Return the methods added to the class at runtime from the Class
            # R/W structure, which also include the base methods.
            yield from rw_ext.methods().entries()
        else:
            # Return the base methods.
            yield from self._ro().methods()

    @property
    def ivars(self) -> Generator[InstanceVariable]:
        yield from self._ro().ivars()

    @property
    def properties(self) -> Generator[ClassProperty]:
        if (rw_ext := self._rw_ext()) is not None:
            # Return the properties added to the class at runtime from the Class
            # R/W structure, which also include the base properties.
            yield from rw_ext.properties().entries()
        else:
            # Return the base properties.
            yield from self._ro().properties()

    @property
    def is_metaclass(self) -> bool:
        return (self._ro().flags() & _ClassRoPtr.RO_META) != 0

    @override
    @property
    def cls(self) -> Class | None:
        if self.is_metaclass:
            # Following this pointer in metaclasses is weird. Users are better
            # served following the superclass chain, instead.
            return None
        return super().cls


class InstanceVariable:
    """
    An Objective-C Instance Variable.

    Instance Variables are NOT objects!
    """

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def offset(self) -> int:
        """
        The offset in bytes of this value from the start of the object instance.
        """
        return pwndbg.aglib.memory.s32(pwndbg.aglib.memory.read_pointer_width(self._ptr))

    @property
    def name(self) -> bytes:
        """
        The name of this instance variable.
        """
        return pwndbg.aglib.memory.string(
            pwndbg.aglib.memory.read_pointer_width(self._ptr + pwndbg.aglib.typeinfo.ptrsize)
        )

    @property
    def typename(self) -> bytes:
        """
        The name of the type of this instance variable.
        """
        return pwndbg.aglib.memory.string(
            pwndbg.aglib.memory.read_pointer_width(self._ptr + pwndbg.aglib.typeinfo.ptrsize * 2)
        )

    @property
    def alignment(self) -> int:
        """
        The alignment of this instance variable, in bytes.
        """
        align_log2 = pwndbg.aglib.memory.u32(self._ptr + pwndbg.aglib.typeinfo.ptrsize * 3)

        # All ones indicates the natural alignment of a pointer.
        if align_log2 == 0xFFFFFFFF:
            return pwndbg.aglib.typeinfo.ptrsize

        return 1 << align_log2

    @property
    def size(self) -> int:
        """
        The size of this instance variable, in bytes.
        """
        return pwndbg.aglib.memory.u32(self._ptr + pwndbg.aglib.typeinfo.ptrsize * 3 + 4)


class ClassProperty:
    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def name(self) -> bytes:
        """
        The name of this class property.
        """
        return pwndbg.aglib.memory.string(pwndbg.aglib.memory.read_pointer_width(self._ptr))

    @property
    def value(self) -> bytes:
        """
        The value of this property.
        """
        return pwndbg.aglib.memory.string(
            pwndbg.aglib.memory.read_pointer_width(self._ptr + pwndbg.aglib.typeinfo.ptrsize)
        )


class Selector:
    """
    An Objective-C Selector.

    Selectors are NOT objects!
    """

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def name(self) -> bytes:
        """
        Retrieves the name of this selector.
        """

        # In the Apple Objective-C runtime, selectors are human-readable strings
        # with unique identities[1]. The identity is simply the pointer to the
        # string itself, guaranteed by the tooling to be unique. To read the
        # name of the selector, then, we can simply follow its identity pointer.
        #
        # [1]: https://web.archive.org/web/20161010081824/http://unixjunkie.blogspot.com/2006/02/nil-and-nil.html
        return pwndbg.aglib.memory.string(self._ptr)


class Method:
    """
    An Objective-C Method Pointer.

    Methods are NOT objects!

    A method pointer can be one of three types: Small, small direct, and big.

    Pointer types are distinguished by the two least significant bits in the
    integer representation of the pointer. A value of `1` is used for both small
    pointer types, while all other values are used to distinguish between the
    signing nuances of big pointers.

    Small pointers 32-bit wide and relative to a given base value. Big pointers
    contain the pointers themselves, and they may or may not be signed.

    Small direct pointers are small pointers that reside in the shared cache, and
    their selectors are relative to @selector(🤯), while the selectors of regular
    small pointers are relative to the pointers themselves.
    """

    def __init__(self, ptr: int):
        self._ptr = ptr

    @property
    def sel(self) -> Selector:
        "The selector this method responds to."
        kind = self._ptr & 3
        base = self._ptr & ~3
        if kind == 1:
            if pwndbg.aglib.macho.shared_cache().is_address_in_shared_cache(base):
                # To resolve selectors of small method pointers in the shared cache,
                # we have to look up the identity of @selector(🤯).
                rel = (
                    pwndbg.aglib.macho.shared_cache().objc_builtin_selectors().lookup("🤯".encode())
                )
                ptr = rel + pwndbg.aglib.memory.s32(base)
            else:
                offset = pwndbg.aglib.memory.s32(base)
                ref = base + offset

                # Non-shared cache values are pointers to selectors.
                ptr = pwndbg.aglib.memory.read_pointer_width(ref)

            return Selector(ptr)
        return Selector(_ptrauth_strip(pwndbg.aglib.memory.read_pointer_width(base)))

    @property
    def types(self) -> bytes:
        "The types of the arguments to this method."
        kind = self._ptr & 3
        base = self._ptr & ~3
        if kind == 1:
            ptr = base + 4
            offset = pwndbg.aglib.memory.s32(ptr)
            addr = ptr + offset
        else:
            ptr = base + 8
            addr = _ptrauth_strip(
                pwndbg.aglib.memory.read_pointer_width(base + pwndbg.aglib.typeinfo.ptrsize)
            )

        return pwndbg.aglib.memory.string(addr)

    @property
    def imp(self) -> int:
        "The pointer to the function that implements this method."
        kind = self._ptr & 3
        base = self._ptr & ~3
        if kind == 1:
            # There's a bit of nuance here.
            #
            # Method swizzling for small pointers is implemented using a global
            # hash map of method pointers to implementation pointers. When
            # getting the IMP pointer for a small pointer, the runtime will
            # first check the global hash map to see if the method has been
            # swizzled, and return the swizzled method if it has. The runtime
            # will do what we do here if method has not been swizzled.
            #
            # Currently, we have no good way to query this map, and no other way
            # to detect that a method has been swizzled, so swizzles to small
            # pointers are unfortunately compeltely invisible to us.
            #
            # TODO: Handle method swizzles for small-pointer-type Objective-C methods.
            ptr = base + 8
            offset = pwndbg.aglib.memory.s32(ptr)
            return ptr + offset
        ptr = base + 16
        return _ptrauth_strip(
            pwndbg.aglib.memory.read_pointer_width(base + pwndbg.aglib.typeinfo.ptrsize)
        )


class _MethodList(_EntList[Method]):
    """
    Method entity list.
    """

    _flags_mask = 0xFFFF0003

    SMALL_METHOD_LIST_FLAG = 0x80000000
    "Indicates that the pointers in this list are small method pointers."

    BIG_SIGNED_METHOD_LIST_FLAG = 0x8000000000000000
    """
    Indicates that the pointers in this list are big and signed.

    Stored as part of the pointer to the method list, rather than in the flags
    field, as is the case with other flags.
    """

    @override
    def _modify_pointer(self, ptr: int) -> int:
        if self.flags() & self.SMALL_METHOD_LIST_FLAG != 0:
            # This is a small pointer list.
            return (ptr & ~3) | 1
        if self._ptr & self.BIG_SIGNED_METHOD_LIST_FLAG:
            # This is a big signed poitner list.
            return (ptr & ~3) | 2
        # No tag or flag. This is a big pointer list.
        return ptr & ~3

    @override
    def _addr_from_ptr(self, ptr: int) -> int:
        # Top-Byte-Ignore is assumed for method lists, but method list pointers
        # may have metadata attached to them.
        return ptr & ~0xFF00000000000000

    @override
    def _from_ptr(self, ptr: int) -> Method:
        return Method(ptr)


class _IVarList(_EntList[InstanceVariable]):
    "IVar entity list."

    _flags_mask = 0

    @override
    def _modify_pointer(self, ptr: int) -> int:
        return ptr

    @override
    def _addr_from_ptr(self, ptr: int) -> int:
        return ptr

    @override
    def _from_ptr(self, ptr: int) -> InstanceVariable:
        return InstanceVariable(ptr)


class _ClassPropertyList(_EntList[ClassProperty]):
    "Class property entity list."

    _flags_mask = 0

    @override
    def _modify_pointer(self, ptr: int) -> int:
        return ptr

    @override
    def _addr_from_ptr(self, ptr: int) -> int:
        return ptr

    @override
    def _from_ptr(self, ptr: int) -> ClassProperty:
        return ClassProperty(ptr)


def _parse_method_type_array(ty: bytes, depth: int) -> tuple[Type, int] | None:
    """
    Parses a typed array entry in an Objective-C method type string.
    """
    if ty[0] != b"[":
        return None
    if (end := ty.find(b"]")) == -1:
        return None
    if (inner := _parse_method_type(ty[1:end], depth + 1)) is None:
        return None

    # Treat arrays as pointers.
    return inner[0].pointer(), inner[1] + 2


def _parse_method_type_pointer(ty: bytes, depth: int) -> tuple[Type, int] | None:
    """
    Parses a typed pointer entry in an Objective-C method type string.
    """
    if ty[0] != b"^":
        return None
    if (inner := _parse_method_type(ty[1:], depth + 1)) is None:
        return None

    return inner[0].pointer(), inner[1] + 1


def _parse_method_type_id_typed(ty: bytes, depth: int) -> tuple[Type, int] | None:
    """
    Parses a typed `id` entry in an Objective-C method type string.
    """
    if ty[:2] != b'@"':
        return None
    if (end := ty.find(b'"', 2)) == -1:
        return None

    # Resolve to `id`, even if we could technically be more specific.
    return pwndbg.aglib.typeinfo.lookup_types("id"), end + 1


def _parse_method_type(ty: bytes, depth: int) -> tuple[Type, int] | None:
    """
    Parses a single entry in an Objective-C method type string.
    """
    if depth > max_method_type_depth.value:
        # Too deep. Reject this type.
        return None

    while ty[0] >= 0x30 and ty[0] < 0x3A:
        # Ignore integers that we don't recognize.
        ty = ty[1:]

    # Try to parse composite types.
    if (res := _parse_method_type_array(ty, depth)) is not None:
        return res
    if (res := _parse_method_type_pointer(ty, depth)) is not None:
        return res
    if (res := _parse_method_type_id_typed(ty, depth)) is not None:
        return res

    # Try to parse atomic types.
    match ty[0:1]:
        case b"v":
            return pwndbg.aglib.typeinfo.void, 1
        case b"f":
            return pwndbg.aglib.typeinfo.lookup_types("float"), 1
        case b"d":
            return pwndbg.aglib.typeinfo.lookup_types("double"), 1
        case b"B":
            return pwndbg.aglib.typeinfo.int32, 1
        case b"*":
            return pwndbg.aglib.typeinfo.char.pointer(), 1
        case b"@":
            return pwndbg.aglib.typeinfo.lookup_types("id"), 1
        case b"#":
            return pwndbg.aglib.typeinfo.lookup_types("Class"), 1
        case b":":
            return pwndbg.aglib.typeinfo.lookup_types("SEL"), 1
        case b"c":
            return pwndbg.aglib.typeinfo.char, 1
        case b"s":
            return pwndbg.aglib.typeinfo.int16, 1
        case b"i":
            return pwndbg.aglib.typeinfo.int32, 1
        case b"l":
            return pwndbg.aglib.typeinfo.int32, 1
        case b"q":
            return pwndbg.aglib.typeinfo.int64, 1
        case b"C":
            return pwndbg.aglib.typeinfo.uchar, 1
        case b"S":
            return pwndbg.aglib.typeinfo.uint16, 1
        case b"I":
            return pwndbg.aglib.typeinfo.uint32, 1
        case b"L":
            return pwndbg.aglib.typeinfo.uint32, 1
        case b"Q":
            return pwndbg.aglib.typeinfo.uint64, 1

    return None


def _parse_method_type_string(ty: bytes) -> Generator[Type | None]:
    """
    Return a generator that yields the type names of the arguments to a method,
    if they can be resolved, yielding `None` for types that we fail to resolve.
    """
    cursor = 0
    yielded = 0
    while yielded < max_method_argument_count.value + 1:
        while cursor < len(ty) and ty[cursor] >= 0x30 and ty[cursor] < 0x3A:
            # Ignore integers.
            cursor += 1

        if cursor >= len(ty):
            break

        res = _parse_method_type(ty[cursor:], 0)

        if res is None:
            yield None
            break

        yield res[0]
        cursor += res[1]
        yielded += 1


max_method_argument_count = pwndbg.config.add_param(
    "objc-max-function-arguments",
    32,
    "maximum number of arguments to resolve for an Objective-C method call",
    param_class=pwndbg.lib.config.PARAM_ZUINTEGER,
)

max_method_type_depth = pwndbg.config.add_param(
    "objc-max-function-types-depth",
    32,
    "maximum allowed depth for a type in an Objective-C method call",
    param_class=pwndbg.lib.config.PARAM_ZUINTEGER,
)


def try_resolve_call_at_current_pc(insn: PwndbgInstruction) -> pwndbg.lib.functions.Function | None:
    """
    Tries to resolve a call to an Objective-C method for an instruction in the
    current Program Counter.
    """
    if not insn.call_like:
        # No point in trying to resolve something that isn't a call.
        return None

    target = pwndbg.aglib.symbol.resolve_addr(insn.target)
    if target == "objc_msgSend":
        # Resolve msgSend.
        #
        # First, try to work out the method implementation from the selector in
        # the current architecture.

        if pwndbg.aglib.arch.name == "aarch64":
            obj_reg = "x0"
            sel_reg = "x1"
        else:
            # Not supported.
            # TODO: Support resolution of Objective-C method calls in x86-64.
            return None

        obj_ptr = pwndbg.aglib.regs.read_reg(obj_reg)
        sel_ptr = pwndbg.aglib.regs.read_reg(sel_reg)

        obj = Object(obj_ptr)
        sel = Selector(sel_ptr)

        # Walk up the class chain and try to find the method value.
        method = None
        clss = obj.cls
        while clss is not None:
            try:
                method = next(method for method in clss.methods if method.sel.name == sel.name)
                break
            except StopIteration:
                pass

            clss = clss.superclass

        if method is None:
            # Could not resolve the method, either an invalid call, or we don't
            # know how to find out the method at runtime. Either way, not much
            # can be done.
            return None

        # Resolve name and number of function arguments from the selector.
        #
        # In Objective-C, the calling convention and number of arguments is
        # fixed at compile time, and no runtime reflection information is used,
        # so there's nothing stopping a program from using a selector that does
        # not at all reflect the real arguments to the method. Still, it is
        # conventional for the selector to be representative.
        #
        # Because of that, we try to extract some information only on a best-
        # effort basis, since we don't know whether it will be truly useful, or
        # if the program is actively trying to confuse us.
        sel_args: list[bytes] = [b"id", b"sel"]
        sel_last_args_idx = 0
        while len(sel_args) < max_method_argument_count.value:
            index = sel.name.find(b":", sel_last_args_idx)
            if index == -1:
                break

            sel_args.append(sel.name[sel_last_args_idx:index])
            sel_last_args_idx = index + 1

        # Resolve type and number of function arguments from the encoded type.
        #
        # Same caveats apply here as do with the selector.
        types = list(_parse_method_type_string(method.types))
        fn_rettype = types[0] if len(types) > 0 else None

        # Build the function using the information we got.
        fn_args: list[pwndbg.lib.functions.Argument] = []
        fn_args_unk_count = 0
        for arg_i in range(max(len(types) - 1, len(sel_args))):
            if arg_i < len(sel_args):
                name = sel_args[arg_i].decode("utf-8", errors="backslashreplace")
            else:
                # Name all arguments we don't have a name for "unknownX:"
                name = f"unknown{fn_args_unk_count}"
                fn_args_unk_count += 1

            if arg_i < len(types) - 1:
                ty = types[arg_i + 1].name_to_human_readable
            else:
                # Treat all arguments we don't know about as being `uintptr_t`s.
                ty = "uintptr_t"

            fn_args.append(pwndbg.lib.functions.Argument(type=ty, name=name, derefcnt=0))

        return pwndbg.lib.functions.Function(
            type=fn_rettype.name_to_human_readable if fn_rettype is not None else "void",
            derefcnt=0,
            name=sel.name.decode("utf-8", errors="backslashreplace"),
            args=fn_args,
        )

    # Not a an Objective-C call or not a type we know about.
    return None
