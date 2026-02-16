from __future__ import annotations

import itertools
import struct
from collections.abc import Callable
from collections.abc import Generator
from typing import Generic
from typing import TypeVar

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol


def _uleb128(ptr: int) -> tuple[int, int]:
    """
    Decode a ULEB128 value at the start of the given address, and return the
    decoded number, along with how many bytes the entire number takes.
    """
    acc = 0
    i = 0
    while True:
        byte = pwndbg.aglib.memory.u8(ptr + i)

        acc |= (byte & 0x7F) << (7 * i)
        if byte & 0x80 == 0:
            # This is the terminator byte.
            break

        i += 1

    return acc, i + 1


class _RawTrie:
    """
    This is the untyped base implementation of Trie.
    """

    def __init__(self, ptr: int):
        self._ptr = ptr

    def _walk(
        self,
        offset: int,
        acc: bytes,
        edgesel: Callable[[bytes, bytes], bool],
        nodesel: Callable[[bytes], bool],
    ) -> Generator[tuple[bytes, int, int]]:
        """
        Walk the trie.

        Allows callers to select edges for exploration and nodes for yielding
        through the `edgesel` and `nodesel` callables.

        At every edge, this function will call `edgesel` with the currently
        accumulated name and the name associated with the edge, and will take
        action according to the value it returns. If it returns True, that edge
        will be explored, otherwise, the edge will be ignored.

        At every node, this function will call `nodesel` with the currently
        accumulated name. If it returns True, the node will be yielded,
        otherwise, it will be ignored.

        Yielded node information consists of a tuple of (name, ptr, length),
        where `name` is the name of the node, `ptr` is the address of the first
        byte of its associated data, and `length` is the length of its
        associated data, in bytes.
        """
        base = self._ptr + offset

        node_data_len, node_data_len_len = _uleb128(base)
        if node_data_len != 0 and nodesel(acc):
            # The user selected this node, stop the walk here.
            yield acc, base + node_data_len_len, node_data_len

        cursor = base + node_data_len_len + node_data_len

        # The number of children is NOT a ULEB128.
        children = pwndbg.aglib.memory.u8(cursor)
        cursor += 1

        for _ in range(children):
            name = pwndbg.aglib.memory.string(cursor)
            cursor += len(name) + 1

            child_offset, child_offset_len = _uleb128(cursor)
            cursor += child_offset_len

            if edgesel(acc, name):
                yield from self._walk(child_offset, acc + name, edgesel, nodesel)

            # The cursor is already at the next child.

    def _get_raw(self, name: bytes) -> tuple[bytes, int, int] | None:
        """
        Get the data associated with the node of given name, if it exists.
        """

        def nodesel(candidate: bytes) -> bool:
            return candidate == name

        def edgesel(acc: bytes, candidate: bytes) -> bool:
            return name[len(acc) :].startswith(candidate)

        return next(self._walk(0, b"", edgesel, nodesel), None)

    def _entries_raw(self) -> Generator[tuple[bytes, int, int]]:
        """
        List all the entries in the trie, along with their associated data.
        """
        yield from self._walk(0, b"", lambda _acc, _candidate: True, lambda _candidate: True)

    def keys(self) -> Generator[bytes]:
        """
        List the name of all nodes in the trie.
        """
        yield from (name for name, _ptr, _size in self._entries_raw())


T = TypeVar("T")


class Trie(_RawTrie, Generic[T]):
    """
    Prefix Tree

    The Mach-O format makes extensive use of prefix trees for any operation that
    involves string-based loookup.
    """

    def __init__(self, ptr: int, ty: Callable[[int, int], T]):
        super().__init__(ptr)
        self._ty = ty

    def get(self, name: bytes) -> T | None:
        """
        Get the data associated with the node of given name, if it exists.
        """
        _, ptr, size = self._get_raw(name)
        return self._ty(ptr, size)

    def entries(self) -> Generator[tuple[bytes, T]]:
        """
        List all the entries in the trie, along with their associated data.
        """
        yield from ((name, self._ty(ptr, size)) for name, ptr, size in self._entries_raw())


def _uleb128_ty(ptr: int, size: int) -> int:
    "The type function of ULEB128 associated data, for use with Trie"

    value, actual_size = _uleb128(ptr)

    # Can fail if the type is wrong or the trie is corrupted.
    assert size == actual_size, "Size mismatch while validating ULEB128"

    return value


class DyldSharedCacheMapping:
    def __init__(self, addr: int, size: int, file_offset: int, max_prot: int, init_prot: int):
        self.addr = addr
        self.size = size
        self.file_offset = file_offset
        self.max_prot = max_prot
        self.init_prot = init_prot


def _lookup8(blob: bytes, level: int) -> int:
    """
    Hashes a variable-length byte array into a 64-bit integer.

    Apple uses a variation of an algorithm published by Bob Jenkins in 1997 on
    Dr. Dobb's Journal, and later republished on their website under the title
    "The Hash"[1]. The version used by Apple was also written by Jenkins[2], but
    does not seem to be mentioned in any of their articles, so I don't couldn't
    gather much information about it besides that it looks like a 64-bit variant
    of the algorithm in the article.

    This function is a direct Python port of the algorithm in [2].

    [1]: https://burtleburtle.net/bob/hash/doobs.html
    [2]: https://burtleburtle.net/bob/c/lookup8.c
    """
    blob = bytearray(blob)
    orig_len = len(blob)

    a = level
    b = level
    c = 0x9E3779B97F4A7C13

    padded = False
    while True:
        blob_len = len(blob)
        if blob_len == 0:
            if not padded:
                # We need to mix one more time if the blob was not padded.
                c += orig_len
                a, b, c = _mix64(a, b, c)

            break

        if blob_len < 24:
            # If the length of the blob is not divisible by 24, we pad it out
            # with zeroes until it is.
            #
            # We must be careful so as to always insert a zero at index 16,
            # which corresponds with the reservation of the length in `c` in the
            # original C code.
            c += orig_len

            blob.extend(b"\0" * (23 - blob_len))
            blob.insert(16, 0)

            padded = True

        a += (
            blob[0]
            + (blob[1] << 8)
            + (blob[2] << 16)
            + (blob[3] << 24)
            + (blob[4] << 32)
            + (blob[5] << 40)
            + (blob[6] << 48)
            + (blob[7] << 56)
        )
        b += (
            blob[8]
            + (blob[9] << 8)
            + (blob[10] << 16)
            + (blob[11] << 24)
            + (blob[12] << 32)
            + (blob[13] << 40)
            + (blob[14] << 48)
            + (blob[15] << 56)
        )
        c += (
            blob[16]
            + (blob[17] << 8)
            + (blob[18] << 16)
            + (blob[19] << 24)
            + (blob[20] << 32)
            + (blob[21] << 40)
            + (blob[22] << 48)
            + (blob[23] << 56)
        )

        a %= 0x10000000000000000
        b %= 0x10000000000000000
        c %= 0x10000000000000000

        a, b, c = _mix64(a, b, c)

        blob = blob[24:]

    return c


def _mix64(a: int, b: int, c: int) -> tuple[int, int, int]:
    """
    Mix 3 64-bit values reversibly.

    This function is part of the Python port of Bob Jenkin's hash algorithm, as
    detailed in `_lookup8`.
    """
    a -= b
    a -= c
    a ^= c >> 43
    a %= 0x10000000000000000

    b -= c
    b -= a
    b ^= a << 9
    b %= 0x10000000000000000

    c -= a
    c -= b
    c ^= b >> 8
    c %= 0x10000000000000000

    a -= b
    a -= c
    a ^= c >> 38
    a %= 0x10000000000000000

    b -= c
    b -= a
    b ^= a << 23
    b %= 0x10000000000000000

    c -= a
    c -= b
    c ^= b >> 5
    c %= 0x10000000000000000

    a -= b
    a -= c
    a ^= c >> 35
    a %= 0x10000000000000000

    b -= c
    b -= a
    b ^= a << 49
    b %= 0x10000000000000000

    c -= a
    c -= b
    c ^= b >> 11
    c %= 0x10000000000000000

    a -= b
    a -= c
    a ^= c >> 12
    a %= 0x10000000000000000

    b -= c
    b -= a
    b ^= a << 18
    b %= 0x10000000000000000

    c -= a
    c -= b
    c ^= b >> 22
    c %= 0x10000000000000000

    return a, b, c


class DyldSharedCacheHashSet:
    """
    A hash set from the DyLD Shared Cache.

    The DyLD Shared Cache uses hash sets in all structures related to Objective-C
    Optimization. This class is an interface to them.
    """

    def __init__(self, ptr: int):
        self._ptr = ptr

        self.capacity = pwndbg.aglib.memory.u32(self._ptr + 0x04)
        self.shift = pwndbg.aglib.memory.u32(self._ptr + 0x0C)
        self.mask = pwndbg.aglib.memory.u32(self._ptr + 0x10)
        self.salt = pwndbg.aglib.memory.u64(self._ptr + 0x18)

        # Mask must always be one minus a power of two. If this fails, it hints
        # that we loaded from an invalid address.
        assert (self.mask + 1).bit_count() == 1

        # Name the offsets of elements in the dynamically-sized portion of the
        # structure (which starts at 0x420).
        self._checkbytes_offset = 0x420 + self.mask + 1
        self._offsets_offset = self._checkbytes_offset + self.capacity

        # Preload the scramble and tab lists, to save on LLDB calls later on.
        self._scramble = pwndbg.aglib.memory.read(self._ptr + 0x20, 0x400)
        self._tab = pwndbg.aglib.memory.read(self._ptr + 0x420, self.mask + 1)

        # It is possible that the offsets array is not aligned. The code in
        # libmacho does not seem to care about this condition, but we should
        # probably watch out if it ever does arise in a real-world scenario.
        assert self._offsets_offset % 4 == 0, "Unaligned offset array in Mach-O perfect hash map"

    def _index_of(self, key: bytes) -> int:
        lookup = _lookup8(key, self.salt)

        tab = lookup & self.mask
        tabbed = self._tab[tab]

        scrambled = struct.unpack("<I", self._scramble[tabbed * 4 : (tabbed + 1) * 4])[0]

        return ((lookup >> self.shift) % 0x100000000) ^ scrambled

    def lookup(self, key: bytes) -> int | None:
        """
        Look up the given key in the hash set.

        Returns a pointer to the key if it is present, None otherwise.
        """
        index = self._index_of(key)

        # In libmacho, Apple uses the checkbytes as a way to quickly reject
        # elements that are not in the list without having to compare the keys,
        # but we currently have no need for that optimization.
        offset = pwndbg.aglib.memory.s32(self._ptr + self._offsets_offset + index * 4)
        if offset == 0:
            return None

        ptr = self._ptr + offset

        val = pwndbg.aglib.memory.string(ptr)
        if val != key:
            return None

        return ptr

    def keys(self) -> Generator[bytes]:
        """
        Returns an iterator over all the keys present in the hash set.
        """
        for i in range(self.capacity):
            offset = pwndbg.aglib.memory.s32(self._ptr + self._offsets_offset + i * 4)
            if offset == 0:
                continue

            yield pwndbg.aglib.memory.string(self._ptr + offset)


class DyldSharedCache:
    """
    Handle to the DyLD Shared Cache in the address space of the inferior.

    The shared cache format handling code in libmacho has multiple paths for
    gathering the same information, depending on a value that is near the
    beggining of the header, which indicates that the format has likely evolved
    quite a bit since its first intoduction.

    The way the version of a given shared cache is determined isn't exactly
    straighforward, and relies on a combination of the `magic` and
    `mappingOffset` values. Fortunately for us, however, when `mappingOffset` is
    used for this purpose, it follows the fairly widely used pattern of using
    the size of the struct to denote its version.
    """

    slide: int
    "The slide value of the DyLD Shared Cache, in bytes."

    def __init__(self, addr: int):
        self.addr = addr

        # Preload a few a few values, to speed things up later.
        self.slide = self._slide()
        images_offset = 0x18 if self._header_size() <= 0x1C4 else 0x1C0
        self._images_base = self.addr + pwndbg.aglib.memory.u32(self.addr + images_offset)
        self.image_count = pwndbg.aglib.memory.u32(self.addr + images_offset + 4)

        # Check whether the images are sorted by loading address.
        self._images_sorted_by_address = all(
            a[1] <= b[1] for a, b in itertools.pairwise(self.images)
        )

    def _header_size(self) -> int:
        """
        The length of the shared cache header, in bytes.
        """
        # Read `mappingOffset` (+0x10) from the structure.
        return pwndbg.aglib.memory.u32(self.addr + 16)

    def mappings(self) -> Generator[DyldSharedCacheMapping]:
        """
        Generate the list of memory mappings in the shared cache.
        """
        if self._header_size() <= 0x138:
            # This header predates `mappingWithSlideOffset` (+0x138), so use the
            # regular `mappingOffset` value and regular mapping structures. Read
            # the number of mapping structures from `mappingCount` (+0x14).
            base = self.addr + self._header_size()
            count = pwndbg.aglib.memory.u32(self.addr + 0x14)

            for i in range(count):
                entry = base + i * 0x20
                yield DyldSharedCacheMapping(
                    pwndbg.aglib.memory.u64(entry),
                    pwndbg.aglib.memory.u64(entry + 8),
                    pwndbg.aglib.memory.u64(entry + 16),
                    pwndbg.aglib.memory.u32(entry + 24),
                    pwndbg.aglib.memory.u32(entry + 28),
                )
        else:
            # We can use `mappingWithSlideOffset` (+0x138) and mapping with
            # slide structures for the mappings. Read the number of mapping
            # structures from `mappingWithSlideCount` (+0x13c).
            base = self.addr + pwndbg.aglib.memory.u32(self.addr + 0x138)
            count = pwndbg.aglib.memory.u32(self.addr + 0x13C)

            for i in range(count):
                entry = base + i * 0x38
                yield DyldSharedCacheMapping(
                    pwndbg.aglib.memory.u64(entry),
                    pwndbg.aglib.memory.u64(entry + 8),
                    pwndbg.aglib.memory.u64(entry + 16),
                    pwndbg.aglib.memory.u32(entry + 48),
                    pwndbg.aglib.memory.u32(entry + 52),
                )

    @property
    def base(self) -> int:
        """
        The base virtual address of the DyLD Shared Cache.
        """
        return self.addr

    @property
    def size(self) -> int:
        """
        The mapped size, in bytes, of the DyLD Shared Cache.
        """
        if self._header_size() >= 0x18C:
            # Use `sharedRegionSize` (+0xe8) as the size of the entire shared
            # region.
            return pwndbg.aglib.memory.u64(self.addr + 0xE8)
        # Find the smallest region that covers all the mappings as the size.
        start = None
        end = None
        for mapping in self.mappings():
            if start is None or start > mapping.addr:
                start = mapping.addr

            this_end = start + mapping.size
            if end is None or end < this_end:
                end = this_end

        # Technically possible, but more likely indicates that we messed up
        # somewhere along the line when interpreting mapping information.
        assert start is not None and end is not None, "No dyld shared cache mappings?"
        assert end >= start

        return end - start

    def _slide(self) -> int:
        "The slide value of the DyLD Shared Cache, in bytes."
        mapping_ptr = self.base + self._header_size()
        mapping_base = pwndbg.aglib.memory.u64(mapping_ptr)

        # Make sure this is the start of the shared cache.
        #
        # Again, technically possible, but this breaks compatibility in a way
        # that we have no idea how to deal with. Better to fail and figure out
        # we're doing something wrong than have to track a random bug back to
        # this point.
        mapping_fileoff = pwndbg.aglib.memory.u64(mapping_ptr + 0x10)
        assert mapping_fileoff == 0, (
            "First mapping of the shared cache is not at the start of the shared cache"
        )

        slide = self.base - mapping_base
        assert slide >= 0, "Slide value is negative, but we don't expect it to be"

        return slide

    @property
    def image_index_trie(self) -> Trie[int] | None:
        """
        The trie of image indices, if available.
        """
        if self._header_size() <= 0x110:
            return None

        trie_unslid = pwndbg.aglib.memory.u64(self.addr + 0x108)
        trie_ptr = trie_unslid + self.slide

        return Trie(trie_ptr, _uleb128_ty)

    def image_base(self, index: int):
        assert self.image_count > index

        return pwndbg.aglib.memory.u64(self._images_base + index * 0x20) + self.slide

    def image_name(self, index: int):
        assert self.image_count > index

        return pwndbg.aglib.memory.string(
            self.addr + pwndbg.aglib.memory.u32(self._images_base + index * 0x20 + 0x18)
        )

    @property
    def images(self) -> Generator[tuple[bytes, int]]:
        # This is a little convoluted, but this function is quite hot and
        # calling the debugger can be quite slow, so pulling in the whole array
        # at once goes a really long way.
        #
        # Yes, even with the extra logic. Python is slow, but it's not as
        # slow as calling LLDB an extra time on every iteration.
        data = pwndbg.aglib.memory.read(self._images_base, 0x20 * self.image_count)

        for i in range(self.image_count):
            base = i * 0x20
            yield (
                pwndbg.aglib.memory.string(
                    self.addr + struct.unpack("<I", data[base + 0x18 : base + 0x1C])[0]
                ),
                struct.unpack("<Q", data[base : base + 8])[0] + self.slide,
            )

    @property
    def images_sorted(self) -> Generator[tuple[bytes, int]]:
        "Same as images, but guaranteed to be sorted by increasing base address"
        if self._images_sorted_by_address:
            # The images are naturally sorted by increasing base address.
            #
            # This should be true the _vast_ majority of the time, and perhaps
            # even all the time. Just connect the generators.
            yield from self.images
        else:
            # The images are sorted in some other order.
            #
            # This should be very rare, but we shoulnd't fail if it happens.
            # Unlike the other cases in which we have to choose whether to fail
            # at or gracefully handle a weird condition, libmacho doesn't seem
            # to rely on this being the case.
            images = list(self.images)
            images.sort(key=lambda image: image[1])

            yield from iter(images)

    def is_address_in_shared_cache(self, addr: int) -> int:
        """
        Whether the given address is in the shared cache.
        """
        return addr >= self.base and addr < self.base + self.size

    def objc_builtin_selectors(self) -> DyldSharedCacheHashSet:
        """
        Looks up the hash table of builtin Objective-C selectors and returns it.
        """
        if self._header_size() > 0x1D8:
            # Use `objcOptsOffset` and the new Objective-C optimizations header
            # to find the address of the symbol hash set.

            objc_opt_offset = pwndbg.aglib.memory.u64(self.addr + 0x1D0)
            objc_opt_ptr = self.addr + objc_opt_offset

            offset = pwndbg.aglib.memory.u64(objc_opt_ptr + 0x18)
            ptr = self.addr + offset

            # Technically possible, but we have *no* idea what to do if this
            # happens, and it's more likely that we got something wrong.
            assert offset != 0, (
                "Tried to query builtin selector identity, but have no Objective-C optimization header?"
            )
        else:
            raise NotImplementedError(
                "Objective-C optimization queries are not yet supported for shared caches that have no objcOptsOffset value"
            )

        return DyldSharedCacheHashSet(ptr)


_global_new_variable_id = 0


@pwndbg.lib.cache.cache_until("objfile")
def shared_cache() -> DyldSharedCache | None:
    """
    Base address of the Darwin shared cache.

    In Darwin, the way the Objective-C Runtime queries for this value is to call
    `_dyld_get_shared_cache_range` from libdyld[1], which then calls a routine
    that lives inside dyld itself, and that returns the values after poking into
    internal C++ structures.

    From our perspective, that kind of sucks. Calling routines from debuggers
    can be quite unreliable, and so ideally we'd always be peeking into the data
    structures directly. But, in this case, even for Apple these are considered
    entirely private to dyld[2], and so there's even less of a stability guarantee
    for the layout of these structures than normal.

    Because of this, a level of care must be taken before calling this function,
    as it must be assumed that the state of the inferior can be changed by it.

    [1]: https://github.com/apple-oss-distributions/objc4/blob/f126469408dc82bd3f327217ae678fd0e6e3b37c/runtime/objc-opt.mm#L434
    [2]: https://github.com/apple-oss-distributions/dyld/blob/main/doc/dyld4.md#libdylddylib
    """
    if pwndbg.aglib.symbol.lookup_symbol("_dyld_get_shared_cache_range") is None:
        return None

    # Due to bug: https://github.com/llvm/llvm-project/issues/84806#issuecomment-1995055683
    # we have to create new variable on each call
    global _global_new_variable_id
    _global_new_variable_id += 1
    var = f"$_pwndbg_internal_shared_cache_size{_global_new_variable_id}"

    base = pwndbg.dbg.selected_inferior().evaluate_expression(
        f"size_t {var} = 0; (const void*)_dyld_get_shared_cache_range(&{var})"
    )
    if base.is_optimized_out:
        return None

    base = int(base)
    if base == 0:
        return None

    return DyldSharedCache(base)
