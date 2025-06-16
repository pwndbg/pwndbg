"""
Implements handling of musl's allocator mallocng.
https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng
"""

from __future__ import annotations

from typing import List

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory as memory
import pwndbg.aglib.typeinfo

# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L14
# Slot granularity.
UNIT = 16
# Size of in-band metadata.
IB = 4

# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L12
# Describes the possible sizes a slot can be. These are `/ UNIT`.
# fmt: off
size_classes: List[int] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 15, 18, 20,
    25, 31, 36, 42, 50, 63, 72, 84, 102, 127, 146,
    170, 204, 255, 292, 340, 409, 511, 584, 682, 818,
    1023, 1169, 1364, 1637, 2047, 2340, 2730, 3276,
    4095, 4680, 5460, 6552, 8191,
]
# fmt: on


# Shorthand
def int_size():
    return pwndbg.aglib.typeinfo.sint.sizeof


class Group:
    """
    A group is an array of slots.

    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L17
    struct group {
      struct meta *meta;
      unsigned char active_idx:5;
      char pad[UNIT - sizeof(struct meta *) - 1];
      unsigned char storage[];
    };
    """

    def __init__(self, addr: int) -> None:
        self.addr = addr

        self._meta = None
        self._active_idx = None

    def preload(self) -> None:
        """
        Read all the necessary process memory to populate the group's
        fields.

        Do this if you know you will be using most of the
        fields of the group. It will be faster, since we can do one
        reads instead of two small ones. You may also catch
        inaccessible memory exceptions here and not worry about it later.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        data = memory.read(self.addr, pwndbg.aglib.arch.ptrsize + 1)
        self._meta = Meta(pwndbg.aglib.arch.unpack(data[: pwndbg.aglib.arch.ptrsize]))
        self._active_idx = data[-1] & 0b11111

    @property
    def meta(self) -> Meta:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._meta is None:
            self._meta = Meta(memory.read_pointer_width(self.addr))

        return self._meta

    @property
    def active_idx(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._active_idx is None:
            self._active_idx = memory.u8(self.addr + pwndbg.aglib.arch.ptrsize) & 0b11111

        return self._active_idx

    @property
    def storage(self) -> int:
        return self.addr + UNIT

    @property
    def group_size(self) -> int:
        """
        The size of this group, in bytes.

        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L234
        return self.meta.stride * self.meta.cnt + UNIT


class Slot:
    """
    The "unit of allocation" (analogous to glibc's "chunk").
    There is no struct in the source code that describes it.
    """

    def __init__(self, p: int) -> None:
        # The start of user memory. It may
        # not be the actual start of the slot.
        self.p: int = p
        self._offset: int = None
        self._idx: int = None
        # Not exactly sure what this is.
        self._check4: int = None

        self._group: Group = None
        self._meta: Meta = None
        self._reserved: int = None

    def preload(self) -> None:
        """
        Read all the necessary process memory to populate the slot's
        fields.

        Do this if you know you will be using most of the
        fields of the slot. It will be faster, since we can do a few
        big reads instead of many small ones. You may also catch
        inaccessible memory exceptions here and not worry about it later.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # Read all the in-band data.
        inband_data = memory.read(self.p - 8, 8)

        self._check4 = inband_data[4]
        if self._check4:
            self._offset = int.from_bytes(inband_data[0:4], pwndbg.aglib.arch.endian, signed=False)
        else:
            self._offset = int.from_bytes(inband_data[6:8], pwndbg.aglib.arch.endian, signed=False)
        idxv = inband_data[5]
        if idxv != 255:
            self._idx = idxv & 31
        else:
            self._idx = 0

        # Read the group's meta pointer.
        _ = self.meta
        # Need this loaded for lots of fields,
        # but we will let it be since we want to be able to
        # say stuff about this slot even with a corrupt meta.
        # _ = self.meta.stride

        self._reserved = inband_data[5] >> 5
        if self._reserved == 5:
            # self.end doesn't need a read.
            self._reserved = memory.u32(self.end - 4)

        # All the other fields are calculated without
        # memory reads.

    @property
    def check4(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L134
        if self._check4 is None:
            self._check4 = memory.u8(self.p - 4)

        return self._check4

    @property
    def offset(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L132
        if self._offset is None:
            if self.check4:
                # assert(!offset);
                self._offest = memory.u32(self.p - 8)
                # assert(offset > 0xffff);
            else:
                self._offset = memory.u16(self.p - 2)

        return self._offset

    @property
    def idx(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L133
        if self._idx is None:
            v = memory.u8(self.p - 3)
            if v != 255:
                self._idx = v & 31
            else:
                # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L29
                self._idx = 0

        return self._idx

    @property
    def group(self) -> Group:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L139
        if self._group is None:
            self._group = Group(self.p - UNIT * self.offset - UNIT)

        return self._group

    @property
    def meta(self) -> Meta:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L140
        if self._meta is None:
            self._meta = Meta(memory.read_pointer_width(self.group.addr))

        return self._meta

    @property
    def start(self) -> int:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L108
        return self.group.storage + self.meta.stride * self.idx

    @property
    def end(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L109
        return self.start + self.meta.stride - IB

    @property
    def reserved(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L161
        # Lots of asserts here..
        if self._reserved is None:
            self._reserved = memory.u8(self.p - 3) >> 5
            if self._reserved == 5:
                self._reserved = memory.u32(self.end - 4)

        return self._reserved

    @property
    def nominal_size(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L159
        return self.end - self.reserved - self.p

    @property
    def user_size(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        return self.nominal_size

    @property
    def slack(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L199
        return (self.meta.stride - self.nominal_size - IB) // UNIT

    @property
    def internal_offset(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L204
        # Not sure why musl saves it, it doesn't seem to use it.
        # We can calculate it more easily than musl does:
        return (self.p - self.start) // UNIT


class Meta:
    """
    The metadata of a group.

    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L24
    struct meta {
      struct meta *prev, *next;
      struct group *mem;
      volatile int avail_mask, freed_mask;
      uintptr_t last_idx:5;
      uintptr_t freeable:1;
      uintptr_t sizeclass:6;
      uintptr_t maplen:8*sizeof(uintptr_t)-12;
    };
    """

    def __init__(self, addr: int) -> None:
        self.addr: int = addr

        self._prev: int = None
        self._next: int = None
        self._mem: int = None
        self._avail_mask: int = None
        self._freed_mask: int = None
        self._last_idx: int = None
        self._freeable: int = None
        self._sizeclass: int = None
        self._maplen: int = None

        self._stride: int = None

    def preload(self) -> None:
        """
        Read all the necessary process memory to populate the meta's
        fields.

        Do this if you know you will be using most of the
        fields of the meta. It will be faster, since we can do a one
        big read instead of many small ones. You may also catch
        inaccessible memory exceptions here and not worry about it later.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        ptrsize = pwndbg.aglib.arch.ptrsize
        endian = pwndbg.aglib.arch.endian

        # Read the whole struct.
        data = memory.read(self.addr, ptrsize * 3 + 2 * int_size() + 8 * ptrsize)

        cur_offset = 0
        self._prev = pwndbg.aglib.arch.unpack(data[cur_offset:ptrsize])
        cur_offset += ptrsize
        self._next = pwndbg.aglib.arch.unpack(data[cur_offset : (cur_offset + ptrsize)])
        cur_offset += ptrsize
        self._mem = pwndbg.aglib.arch.unpack(data[cur_offset : (cur_offset + ptrsize)])
        cur_offset += ptrsize
        self._avail_mask = int.from_bytes(
            data[cur_offset : (cur_offset + int_size())], endian, signed=False
        )
        cur_offset += int_size()
        self._freed_mask = int.from_bytes(
            data[cur_offset : (cur_offset + int_size())], endian, signed=False
        )
        cur_offset += int_size()
        # I think this is how I should read a bitfield.
        # http://mjfrazer.org/mjfrazer/bitfields/
        flags = int.from_bytes(data[cur_offset : (cur_offset + ptrsize)], endian, signed=False)
        self._last_idx = flags & 0b11111
        self._freeable = (flags >> 5) & 1
        self._sizeclass = (flags >> 6) & 0b111111
        self._maplen = flags >> 12

        # All the other fields are calculated without
        # memory reads.

    @property
    def prev(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._prev is None:
            self._prev = memory.read_pointer_width(self.addr)

        return self._prev

    @property
    def next(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._next is None:
            self._next = memory.read_pointer_width(self.addr + pwndbg.aglib.arch.ptrsize)

        return self._next

    @property
    def mem(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._mem is None:
            self._mem = memory.read_pointer_width(self.addr + pwndbg.aglib.arch.ptrsize * 2)

        return self._mem

    @property
    def avail_mask(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._avail_mask is None:
            # While the type is technically a signed int, it makes more
            # sense to interpret it as unsigned semantically.
            self._avail_mask = memory.uint(self.addr + pwndbg.aglib.arch.ptrsize * 3)

        return self._avail_mask

    @property
    def freed_mask(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._freed_mask is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + int_size()
            # Technically signed.
            self._freed_mask = memory.uint(self.addr + offset)

        return self._freed_mask

    @property
    def last_idx(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._last_idx is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + int_size() * 2
            # reading pointer width so it works regardless of endianness
            self._last_idx = memory.read_pointer_width(self.addr + offset) & 0b11111

        return self._last_idx

    @property
    def freeable(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._freeable is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + int_size() * 2
            self._freeable = (memory.read_pointer_width(self.addr + offset) >> 5) & 1

        return self._freeable

    @property
    def sizeclass(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._sizeclass is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + int_size() * 2
            self._sizeclass = (memory.read_pointer_width(self.addr + offset) >> 6) & 0b111111

        return self._sizeclass

    @property
    def maplen(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._maplen is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + int_size() * 2
            self._maplen = memory.read_pointer_width(self.addr + offset) >> 12

        return self._maplen

    @property
    def stride(self):
        """
        Returns -1 if sizeclass >= len(size_classes).
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L175
        if self._stride is None:
            if not self.last_idx and self.maplen:
                self._stride = self.maplen * 4096 - UNIT
            else:
                if self.sizeclass < len(size_classes):
                    self._stride = UNIT * size_classes[self.sizeclass]
                else:
                    # The meta is corrupted.
                    self._stride = -1

        return self._stride

    @property
    def cnt(self):
        """
        Number of slots in the group.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L60
        return self.last_idx + 1

    @property
    def slot_size(self):
        """
        The size of a slot in this group, in bytes.

        Returns -1 if sizeclass >= len(size_classes).
        """
        if self.sizeclass < len(size_classes):
            return size_classes[self.sizeclass] * UNIT
        else:
            # The meta is corrupted.
            return -1


class MetaArea:
    def __init__(self, addr: int) -> None:
        self.addr = addr


class Mallocng:
    pass
