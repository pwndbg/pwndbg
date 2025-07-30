from __future__ import annotations

from typing import Generator

import pwndbg
import pwndbg.aglib.memory


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

        # Name the offsets of elements in the dynamically-sized portion of the
        # structure (which starts at 0x420).
        self._checkbytes_offset = 0x420 + self.mask + 1
        self._offsets_offset = self._checkbytes_offset + self.capacity

        # It is possible that the offsets array is not aligned. The code in
        # libmacho does not seem to care about this condition, but we should
        # probably watch out if it ever does arise in a real-world scenario.
        assert self._offsets_offset % 4 == 0, "Unaligned offset array in Mach-O perfect hash map"

    def _scramble(self, index: int) -> int:
        assert index < 256
        return pwndbg.aglib.memory.u32(self._ptr + 0x20 + index * 4)

    def _tab(self, index: int) -> int:
        assert index & ~self.mask == 0
        return pwndbg.aglib.memory.u8(self._ptr + 0x420 + index)

    def _index_of(self, key: bytes) -> int:
        lookup = _lookup8(key, self.salt)
        return ((lookup >> self.shift) % 0x100000000) ^ self._scramble(
            self._tab(lookup & self.mask)
        )

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

    def __init__(self, addr: int):
        self.addr = addr

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

    def base(self) -> int:
        """
        The base virtual address of the DyLD Shared Cache.
        """
        return self.addr

    def size(self) -> int:
        """
        The mapped size, in bytes, of the DyLD Shared Cache.
        """
        if self._header_size() >= 0x18C:
            # Use `sharedRegionSize` (+0xe8) as the size of the entire shared
            # region.
            return pwndbg.aglib.memory.u64(self.addr + 0xE8)
        else:
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

    def is_address_in_shared_cache(self, addr: int) -> int:
        """
        Whether the given address is in the shared cache.
        """
        return addr >= self.base() and addr < self.base() + self.size()

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
            assert (
                offset != 0
            ), "Tried to query builtin selector identity, but have no Objective-C optimization header?"
        else:
            raise NotImplementedError(
                "Objective-C optimization queries are not yet supported for shared caches that have no objcOptsOffset value"
            )

        return DyldSharedCacheHashSet(ptr)


@pwndbg.lib.cache.cache_until("exit")
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
    base = int(
        pwndbg.dbg.selected_inferior().evaluate_expression(
            "(const void*)_dyld_get_shared_cache_range()"
        )
    )

    if base == 0:
        return None

    return DyldSharedCache(base)
