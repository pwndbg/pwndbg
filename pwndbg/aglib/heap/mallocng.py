"""
Implements handling of musl's allocator mallocng.
https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng
"""

from __future__ import annotations

from enum import Enum
from typing import List
from typing import Optional
from typing import Tuple

from typing_extensions import override

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.heap.heap
import pwndbg.aglib.memory as memory
import pwndbg.aglib.stack
import pwndbg.aglib.typeinfo
import pwndbg.color.message as message

# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L14
# Slot granularity.
UNIT: int = 16
# Size of in-band metadata.
IB: int = 4

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


class SlotState(Enum):
    ALLOCATED = "allocated"
    FREED = "freed"
    # Available - this slot has not yet been allocated.
    AVAIL = "available"


# Shorthand
def int_size() -> int:
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

    def set_meta(self, meta: Meta) -> None:
        """
        Sets the meta object for this group.

        If the meta for this group is already calculated by the callee,
        use this to prevent it from being wastefully recalculated.
        """
        self._meta = meta

    def at_index(self, idx: int) -> int:
        """
        Get the address of the slot at index idx.
        """
        return self.storage + idx * self.meta.stride


class Slot:
    """
    The "unit of allocation" (analogous to glibc's "chunk").
    There is no struct in the source code that describes it.
    """

    def __init__(self, p: int) -> None:
        # The start of user memory. It may
        # not be the actual start of the slot.
        self.p: int = p

        # == The p header fields.
        self._offset: int = None
        # p[-3]. Stores lot's of different kinds of
        # information.
        self._pn3: int = None
        self._idx: int = None
        self._reserved_hd: int = None
        self._big_offset_check: int = None
        # ==

        # == The footer fields.
        self._reserved_ft: int = None
        # ==

        # == The start header fields.
        self._start: int = None
        self._cyclic_offset: int = None
        # start[-3]. Stores whether we are cyclic.
        self._startn3: int = None
        # ==

        self._reserved: int = None
        self._group: Group = None
        self._meta: Meta = None
        self._slot_state: SlotState = None

    def preload(self) -> None:
        """
        Read all the necessary process memory to populate the slot's
        p header fields.

        Do this if you know you will be using most of the
        fields of the slot. It will be faster, since we can do a few
        big reads instead of many small ones. You may also catch
        inaccessible memory exceptions here and not worry about it later.

        Fields dependant on the meta are not loaded - you will still
        need to worry about exceptions coming from them.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # == Read the p header.
        pheader = memory.read(self.p - 8, 8)

        self._big_offset_check = pheader[4]
        if self._big_offset_check:
            self._offset = int.from_bytes(pheader[0:4], pwndbg.aglib.arch.endian, signed=False)
        else:
            self._offset = int.from_bytes(pheader[6:8], pwndbg.aglib.arch.endian, signed=False)
        self._pn3 = pheader[5]
        # ==

        # To calculate footer and start header fields
        # we need self.meta.stride. However we want to be able to
        # return some information even if the meta is corrupt or
        # unreachable (e.g. this slot is freed or avail), so
        # we won't load that here.

        # Other fields are calculated without memory reads.

    def preload_meta_dependants(self) -> None:
        """
        Preloads all fields that depend on a sane meta.

        It generally only makes sense to run this after preload().
        Calling this reduces the amount of process writes and centralizes
        field exceptions to this function.

        If both preload() and preload_meta_dependants() return without
        exceptions, all the fields in this class are guaranteed to not
        cause any more memory reads nor raise any more exceptions.

        Raises:
            pwndbg.dbg_mod.Error: When the meta is corrupt and/or
                reading memory fails.
        """
        # Make sure stride is valid.
        _ = self.meta.stride

        # Read the start header only if we need to.
        if self.start != self.p:
            startheader = memory.read(self.start - 3, 3)
            self._startn3 = int.from_bytes(startheader[0:1], pwndbg.aglib.arch.endian, signed=False)
            self._cyclic_offset = int.from_bytes(
                startheader[1:3], pwndbg.aglib.arch.endian, signed=False
            )

        # Read footer.
        if self.reserved_in_header != 5:
            self._reserved_ft = -1
        else:
            self._reserved_ft = memory.u32(self.end - 4)

        # Other fields are calculated without memory reads.

    # p header fields..

    @property
    def offset(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L132
        if self._offset is None:
            if self.big_offset_check:
                # This can only happen in aligned allocations, which is kind of
                # weird. All allocations of this size are probably mmaped.
                # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/aligned_alloc.c#L49
                self._offest = memory.u32(self.p - 8)
            else:
                self._offset = memory.u16(self.p - 2)

        return self._offset

    @property
    def pn3(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._pn3 is None:
            self._pn3 = memory.u8(self.p - 3)

        return self._pn3

    @property
    def idx(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L133
        if self._idx is None:
            if self.pn3 == 255:
                # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L29
                self._idx = 0
            else:
                self._idx = self.pn3 & 31

        return self._idx

    @property
    def reserved_in_header(self) -> int:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L193
        if self._reserved_hd is None:
            self._reserved_hd = self.pn3 >> 5

        return self._reserved_hd

    @property
    def big_offset_check(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L134
        if self._big_offset_check is None:
            self._big_offset_check = memory.u8(self.p - 4)

        return self._big_offset_check

    # start header fields..

    @property
    def start(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # We have this if-statement so Slot.from_start() can
        # populate _start, giving us lots of fields even with
        # a corrupt meta.
        if self._start is None:
            # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L108
            self._start = self.group.storage + self.meta.stride * self.idx

        return self._start

    @property
    def cyclic_offset(self) -> int:
        """
        Returns zero if is_cyclic() is False.

        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L216
        # Not sure why musl saves it, it doesn't seem to use it.
        # We could calculate it more easily than musl does `(self.p - self.start) // UNIT`
        # but let's report the actual in-band metadata in case the structure
        # is partially corrupted.
        if self._cyclic_offset is None:
            if self.is_cyclic():
                self._cyclic_offset = memory.u16(self.start - 2)
            else:
                self._cyclic_offset = 0

        return self._cyclic_offset

    @property
    def startn3(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        if self._startn3 is None:
            if self.p == self.start:
                # No need to read memory twice.
                self._startn3 = self.pn3
            else:
                self._startn3 = memory.u8(self.start - 3)

        return self._startn3

    # footer fields..

    @property
    def reserved_in_footer(self) -> int:
        """
        Returns -1 if the value is invalid, i.e.
        reserved_in_header() != 5.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L161
        if self._reserved_ft is None:
            if self.reserved_in_header != 5:
                self._reserved_ft = -1
            else:
                self._reserved_ft = memory.u32(self.end - 4)

        return self._reserved_ft

    # code variables..

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
        Returns 0 if reserved_in_header() == 6.
        Returns -1 if reserved_in_header() == 7.

        Raises:
            pwndbg.dbg_mod.Error: When reading memory fails.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L161
        # Lots of asserts here..
        if self._reserved is None:
            if self.reserved_in_header < 5:
                self._reserved = self.reserved_in_header
            elif self.reserved_in_header == 5:
                self._reserved = self.reserved_in_footer
            elif self.reserved_in_header == 6:
                # See contains_group()
                self._reserved = 0
            else:
                # Value forced due to bit-size.
                assert self.reserved_in_header == 7
                # It is possible for start[-3] to contain (7<<5),
                # but p[-3] shouldn't unless the slot is free.
                return -1

        return self._reserved

    @property
    def nominal_size(self) -> int:
        """
        Raises:
            pwndbg.dbg_mod.Error: When reading meta fails.
        """
        # Special case (probably) freed chunks:
        if self.reserved == -1:
            return 0

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

    # custom..

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
    def slot_state(self) -> SlotState:
        if self._slot_state is None:
            # The actual "source of truth" for slot allocation state is
            # self.meta.slotstate_at_index() however we can only resolve
            # the meta if the state is ALLOCATED.
            # We will do a heuristic check that should be good in most cases.

            meta_says: SlotState = None
            try:
                meta_says = self.meta.slotstate_at_index(self.idx)
            except pwndbg.dbg_mod.Error:
                # We can't reach the meta. Either the slot is not allocated
                # or it is allocated but the meta pointer is corrupted.
                meta_says = None

            if meta_says is not None:
                self._slot_state = meta_says
            else:
                # When a slot is freed, its p[-3] gets set to 0xFF so the
                # offset to group start (and by extension, meta) is unrecoverable.
                # We will check for this, although musl only ever sets this
                # and never uses this as a source of truth.
                if self.pn3 == 0xFF:
                    # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L112
                    self._slot_state = SlotState.FREED
                else:
                    self._slot_state = SlotState.AVAIL

        return self._slot_state

    # checks..

    def is_cyclic(self) -> int:
        """
        Returns whether mallocng reports that p != start.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L217
        # We could of course just do `return p != start`
        # but we want to report the actual metadata in case the structure
        # is partially corrupted.
        return self.startn3 == 224

    def contains_group(self) -> bool:
        """
        Does this slot nest a group?
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L269
        return self.reserved_in_header == 6

    # external setters..

    def set_group(self, group: Group) -> None:
        """
        If the slot is FREED or AVAIL, it is impossible for it to
        recover the start of its group, and ergo its meta.

        You can thus use this to set it externally.
        """
        self._group = group

    # constructors..

    @classmethod
    def from_p(cls, p: int) -> "Slot":
        return cls(p)

    @classmethod
    def from_start(cls, start: int) -> "Slot":
        # We need to check if we are cyclic or not.
        # See is_cyclic() and cyclic_offset() logic.
        sn3 = memory.u8(start - 3)
        if sn3 == 224:
            off = memory.u16(start - 2)
            obj = cls(start + off * UNIT)
            obj._sn3 = sn3
        else:
            # freed / avail slots will also go into this branch.
            obj = cls(start)
            obj._sn3 = obj._pn3 = sn3

        obj._start = start

        return obj


class GroupedSlot:
    """
    This is *not* a mallocng concept, this is a pwndbg abstraction.

    A Slot object uses its inband metadata to recover all its fields and
    uncover more information about itself by locating its group and meta.
    It works essentially the same way mallocng's free() works.

    However, if a slot is freed or available, most of its in-band metadata
    will be invalid and it will not be able to recover group and meta. But,
    given the start of the slot, we can infer which group it belongs to and
    what its index is by walking allocator state i.e. ctx i.e. by using
    Mallocng.find_slot().

    A GroupedSlot then describes all information we can glean about a slot
    which is described by a (group, idx) pair. Many of its fields can be
    completely different from a Slot at the same location. They are guaranteed
    to be the same only if the slot is ALLOCATED and hasn't been corrupted.

    Not all fields that are available in Slot are available in GroupedSlot.

    Make sure the group you are passing to the constructor points to a valid meta
    object.
    """

    def __init__(self, group: Group, idx: int) -> None:
        self.group = group
        self.meta = self.group.meta
        self.idx = idx
        self.stride = self.meta.stride
        self.slot_state = self.meta.slotstate_at_index(self.idx)
        self.start = self.group.storage + self.meta.stride * self.idx
        self.end = self.start + self.stride - IB


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
        data = memory.read(self.addr, Meta.sizeof())

        cur_offset = 0

        def next_int(size: int, signed: bool = False) -> int:
            nonlocal cur_offset
            val = int.from_bytes(data[cur_offset : (cur_offset + size)], endian, signed=signed)
            cur_offset += size
            return val

        self._prev = next_int(ptrsize)
        self._next = next_int(ptrsize)
        self._mem = next_int(ptrsize)
        self._avail_mask = next_int(int_size())
        self._freed_mask = next_int(int_size())
        # I think this is how I should read a bitfield.
        # http://mjfrazer.org/mjfrazer/bitfields/
        flags = next_int(ptrsize)
        self._last_idx = flags & 0b11111
        self._freeable = (flags >> 5) & 1
        self._sizeclass = (flags >> 6) & 0b111111
        self._maplen = flags >> 12

        assert cur_offset == Meta.sizeof()

        # All other values are calculated without
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

    # Semi-custom methods..

    @property
    def stride(self) -> int:
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

    # Custom methods..

    @property
    def cnt(self) -> int:
        """
        Number of slots in the group.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L60
        return self.last_idx + 1

    @property
    def is_donated(self) -> bool:
        """
        Returns whether the group object referred to by this meta has been
        created by being donated by ld.
        """
        # When mapped object files contain unused memory, they are donated
        # to the heap. See https://elixir.bootlin.com/musl/v1.2.5/source/ldso/dynlink.c#L600
        # and https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L36 .
        # Only in this case is `meta.freeable = 0;`
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/donate.c#L25
        return not self.freeable

    @property
    def is_mmaped(self) -> bool:
        """
        Returns whether the group object referred to by this meta has been
        created by being mmaped.
        """
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L177
        # The if-statement in the source also checks for !g->last_idx but in practice
        # I've seen this value be non-zero for mmap()-ed groups, so we're leaving it out.
        return not self.is_donated and bool(self.maplen)

    @property
    def is_nested(self) -> bool:
        """
        Returns whether the group object referred to by this meta has been
        created by being nested into a slot.
        """
        return not self.is_donated and not self.is_mmaped

    def parent_group(self) -> int:
        """
        If this group is nested, returns the address of the group which
        contains the slot in which this group is in. Otherwise, returns -1.
        """
        if not self.is_nested:
            return -1

        return Slot(Group(self.mem).addr).group.addr

    def root_group(self) -> Group:
        """
        Returns the topmost/biggest parent group. It will never be a nested
        group. If this group isn't nested, this group is returned.
        """
        cur: Group = Group(self.mem)

        while cur.meta.is_nested:
            cur = Slot(cur.addr).group

        return cur

    def slotstate_at_index(self, idx: int) -> SlotState:
        me = 1 << idx
        if self.freed_mask & me:
            return SlotState.FREED
        elif self.avail_mask & me:
            return SlotState.AVAIL
        else:
            return SlotState.ALLOCATED

    @staticmethod
    def sizeof() -> int:
        return 2 * int_size() + 4 * pwndbg.aglib.arch.ptrsize


class MetaArea:
    """
    Slabs that contain metas, linked in a singly-linked list.

    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L34
    struct meta_area {
      uint64_t check;
      struct meta_area *next;
      int nslots;
      struct meta slots[];
    };
    """

    def __init__(self, addr: int) -> None:
        self.addr: int = addr

        self.check: int = 0
        self.meta_area: int = 0
        self.nslots: int = 0
        self.slots: int = 0

        self.load()

    def load(self) -> None:
        ptrsize = pwndbg.aglib.arch.ptrsize
        uint64size = pwndbg.aglib.typeinfo.uint64.sizeof
        endian = pwndbg.aglib.arch.endian

        data: bytearray = memory.read(self.addr, uint64size + ptrsize + int_size())

        cur_offset = 0

        def next_int(size: int, signed: bool = False) -> int:
            nonlocal cur_offset
            val = int.from_bytes(data[cur_offset : (cur_offset + size)], endian, signed=signed)
            cur_offset += size
            return val

        self.check = next_int(uint64size)
        self.next = next_int(ptrsize)
        self.nslots = next_int(int_size(), True)

        # Alignment adjustment
        cur_offset += ptrsize - int_size()

        self.slots = self.addr + cur_offset

    def at_index(self, idx: int) -> int:
        """
        Returns the address of the meta object located
        at index idx.
        """
        return self.slots + idx * Meta.sizeof()

    @property
    def area_size(self) -> int:
        """
        Returns not the size of `struct meta_area` but rather
        the size of the memory this object represents.
        """
        return (self.slots - self.addr) + self.nslots * Meta.sizeof()


class MallocContext:
    """
    The global object that holds all allocator state.

    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L41
    struct malloc_context {
      uint64_t secret;
    #ifndef PAGESIZE
      size_t pagesize;
    #endif
      int init_done;
      unsigned mmap_counter;
      struct meta *free_meta_head;
      struct meta *avail_meta;
      size_t avail_meta_count, avail_meta_area_count, meta_alloc_shift;
      struct meta_area *meta_area_head, *meta_area_tail;
      unsigned char *avail_meta_areas;
      struct meta *active[48];
      size_t usage_by_class[48];
      uint8_t unmap_seq[32], bounces[32];
      uint8_t seq;
      uintptr_t brk;
    };
    """

    def __init__(self, addr: int) -> None:
        self.addr: int = addr

        self.secret: int = 0
        self.pagesize: int = 0
        self.init_done: int = 0
        self.mmap_counter: int = 0
        self.free_meta_head: int = 0
        self.avail_meta: int = 0
        self.avail_meta_count: int = 0
        self.avail_meta_area_count: int = 0
        self.meta_alloc_shift: int = 0
        self.meta_area_head: int = 0
        self.meta_area_tail: int = 0
        self.avail_meta_areas: int = 0
        self.active: List[int] = []
        self.usage_by_class: List[int] = []
        self.unmap_seq: List[int] = []
        self.bounces: List[int] = []
        self.seq: int = 0
        self.brk: int = 0

        self.sizeof: int = 0
        self.has_pagesize_field: bool = False

        self.load()

    def load(self) -> None:
        ptrsize = pwndbg.aglib.arch.ptrsize
        size_tsize = pwndbg.aglib.typeinfo.size_t.sizeof
        unsignedsize = pwndbg.aglib.typeinfo.uint.sizeof
        uint8size = pwndbg.aglib.typeinfo.uint8.sizeof
        uint64size = pwndbg.aglib.typeinfo.uint64.sizeof
        endian = pwndbg.aglib.arch.endian

        # We will assume the struct has the pagesize field at first (even though it usually
        # doesn't), which allows us to only do one memory read. This is 0x3A8 bytes on x86_64.
        self.sizeof = uint64size + size_tsize + int_size() + unsignedsize + ptrsize * 2
        self.sizeof += size_tsize * 3 + ptrsize * 2 + ptrsize + ptrsize * 48 + size_tsize * 48
        self.sizeof += uint8size * 32 * 2 + uint8size + (ptrsize - uint8size) + ptrsize

        data: bytearray = memory.read(self.addr, self.sizeof)

        cur_offset = 0

        def next_int(size: int, signed: bool = False) -> int:
            nonlocal cur_offset
            val = int.from_bytes(data[cur_offset : (cur_offset + size)], endian, signed=signed)
            cur_offset += size
            return val

        self.secret = next_int(uint64size)

        # We will read `int` bytes past the `secret`. The `init_done` field can only contain
        # values 0 and 1, so if we get that we know the struct doesn't have the pagesize field.
        # If it contains a value > 1 it must be describing a page size.
        something = int.from_bytes(
            data[cur_offset : (cur_offset + int_size())], endian, signed=True
        )
        self.has_pagesize_field = something > 1

        if self.has_pagesize_field:
            self.pagesize = next_int(size_tsize)
            self.init_done = next_int(int_size(), True)
        else:
            self.init_done = something
            cur_offset += int_size()

            # Fix our assumption, we don't have `size_t pagesize` field.
            self.sizeof -= size_tsize

        self.mmap_counter = next_int(unsignedsize)
        self.free_meta_head = next_int(ptrsize)
        self.avail_meta = next_int(ptrsize)
        self.avail_meta_count = next_int(size_tsize)
        self.avail_meta_area_count = next_int(size_tsize)
        self.meta_alloc_shift = next_int(size_tsize)
        self.meta_area_head = next_int(ptrsize)
        self.meta_area_tail = next_int(ptrsize)
        self.avail_meta_areas = next_int(ptrsize)

        assert len(size_classes) == 48

        for i in range(len(size_classes)):
            cur_active = next_int(ptrsize)
            self.active.append(cur_active)

        for i in range(len(size_classes)):
            cur_usage = next_int(size_tsize)
            self.usage_by_class.append(cur_usage)

        for i in range(32):
            cur_seq = next_int(uint8size)
            self.unmap_seq.append(cur_seq)

        for i in range(32):
            cur_bounce = next_int(uint8size)
            self.bounces.append(cur_bounce)

        self.seq = next_int(uint8size)

        # Adjust for alignment
        cur_offset += ptrsize - uint8size

        self.brk = next_int(ptrsize)

        assert cur_offset == self.sizeof

    def looks_valid(self) -> bool:
        """
        Returns true if this object looks like a valid `struct malloc_context` object
        describing an initialized heap. False otherwise.

        This is used by `class Mallocng` to find the correct ctx object.

        We consider it invalid if the heap reads as uninitialized because:
        1. Performing this check filters out invalid ctx objects very well.
        2. When musl is dynmically linked, due to the ld donation logic,
           the heap will usually be initialized before the start of main().
        """
        if self.init_done != 1:
            return False

        if self.secret <= 0x0000FFFFFFFFFFFF:
            # 1 / 65536 chance this is a false negative.
            return False

        return True


class Mallocng(pwndbg.aglib.heap.heap.MemoryAllocator):
    """
    Tracks the allocator state.
    By leveraging the __malloc_context symbol.

    Import this singleton class like:
    from pwndbg.aglib.heap.mallocng import mallocng as ng

    and make sure that you have run ng.init_if_needed()
    before you used the object.
    """

    def __init__(self) -> None:
        self.finished_init: bool = False

        self.ctx_addr: int = 0
        self.ctx: Optional[MallocContext] = None
        self.has_debug_syms: bool = False

    def init_if_needed(self) -> bool:
        """
        We want this class to be a singleton, but also we can't
        initialize it as soon as pwndbg is loaded.

        Users of the object are responsible for calling this to
        make sure the object is initialized. This also ensures
        our view of the heap is up-to-date.

        Returns:
            True if this object is successfully initialized (whether
            now or before). False otherswise. If this returns False
            you may not use this object for heap operations.
        """
        if self.finished_init:
            # Whoever called init_if_needed() needs to use the Mallocng
            # class, which needs an up-to-date view of __malloc_context,
            # so we will update it here.
            self.ctx.load()
            return True

        self.ctx_addr = 0
        self.ctx = None
        self.has_debug_syms = False

        # We will go in optimistically, and let set_ctx_addr() potentially
        # prove us wrong.
        self.finished_init = True
        self.set_ctx_addr()

        # If we failed, we will try again next time.

        return self.finished_init

    def set_ctx_addr(self) -> None:
        """
        Find where the __malloc_context global symbol is. Try using debug information,
        but if it isn't available try using a heuristic.
        """
        uint64size = pwndbg.aglib.typeinfo.uint64.sizeof

        self.ctx_addr = pwndbg.aglib.symbol.lookup_symbol_addr("__malloc_context")
        if self.ctx_addr is not None:
            self.has_debug_syms = True
            self.ctx = MallocContext(self.ctx_addr)
            return

        # No debug information :(
        self.ctx_addr = 0
        self.has_debug_syms = False

        # We will find the __malloc_context object by searching memory for
        # the secret.
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L50
        # Extract the secret first.
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/glue.h#L49
        at_random = int(pwndbg.auxv.get()["AT_RANDOM"])
        secret = memory.read(at_random + 8, uint64size)

        secret_matches = list(
            pwndbg.search.search(secret, executable=False, writable=True, aligned=uint64size)
        )

        # There are going to be multiple matches. We don't
        # want those on the stack (actual AT_RANDOM) or heap
        # (structures copying the secret). We want it either from the libc.so
        # mapping (if musl is dynamically linked) or the executable's
        # mapping (if musl is statically linked).
        possible: List[Tuple[int, str]] = []
        thread_stacks = pwndbg.aglib.stack.get().values()

        for sm in secret_matches:
            if any(sm in stack_page for stack_page in thread_stacks):
                continue

            mapping_name = pwndbg.aglib.vmmap.find(sm).objfile
            if "[heap" in mapping_name:
                continue

            possible.append((sm, mapping_name))

        if not possible:
            print(message.error("Couldn't find __malloc_context, even with heuristic."))
            print(message.error("Musl mallocng commands will not work.\n"))
            self.ctx_addr = 0
            self.finished_init = False
            return

        known_invalid: set[int] = set()

        if pwndbg.dbg.selected_inferior().is_dynamically_linked():
            for addr, mapname in possible:
                if mapname.endswith("libc.so"):
                    maybe_ctx = MallocContext(addr)
                    if maybe_ctx.looks_valid():
                        self.ctx_addr = addr
                        self.ctx = maybe_ctx
                        return
                    else:
                        known_invalid.add(addr)

            for addr, mapname in possible:
                if "libc" in mapname and addr not in known_invalid:
                    maybe_ctx = MallocContext(addr)
                    if maybe_ctx.looks_valid():
                        self.ctx_addr = addr
                        self.ctx = maybe_ctx
                        return
                    else:
                        known_invalid.add(addr)

            print(
                message.warn(
                    "Couldn't find __malloc_context in a 'libc' mapping, trying elsewhere."
                )
            )
        else:
            # Statically linked.
            # TODO: We should find the Executable Object in the mappings
            # and use that to determine which match is correct. Not sure
            # how to do that though so fall through for now.
            pass

        for addr, mapname in possible:
            if addr not in known_invalid:
                maybe_ctx = MallocContext(addr)
                if maybe_ctx.looks_valid():
                    self.ctx_addr = addr
                    self.ctx = maybe_ctx
                    break

        if self.ctx_addr == 0 or self.ctx is None:
            print(
                message.error(
                    "Couldn't find a valid looking __malloc_context, even with heuristic."
                )
            )
            print(
                message.error(
                    "Musl mallocng commands will not work. Is the allocator initialized?\n"
                )
            )
            self.ctx_addr = 0
            self.ctx = None
            self.finished_init = False
            return

        # Tell the user we found __malloc_context but in an unexpected place.
        if pwndbg.dbg.selected_inferior().is_dynamically_linked():
            print(
                message.warn(
                    f"Found a match @ {self.ctx_addr:#x}. A bit suspicious but we will roll with it.\n"
                )
            )

    @override
    def libc_has_debug_syms(self) -> bool:
        return self.has_debug_syms

    def find_slot(
        self, address: int, metadata: bool = False, shallow: bool = False
    ) -> Tuple[Optional[GroupedSlot], Optional[Slot]]:
        """
        Get the slot which contains this address.

        We say a slot "contains" an address, if the address is in
        [start, start + stride). Thus, this will match the previous
        slot if you provide the address of the header inband metadata
        of a slot.

        If `metadata` is True, then we check [start - IB, end) for
        containment.

        If `shallow` is True, return the biggest slot which contains this
        address. The group that owns this slot will not be a nested group.

        Returns (None, None) if nothing is found.
        """
        metadata_offset = IB if metadata else 0
        # The group which contains a slot which contains `address`.
        hit_group: Optional[Group] = None

        meta_area_addr = self.ctx.meta_area_head
        while meta_area_addr:
            try:
                meta_area = MetaArea(meta_area_addr)
            except pwndbg.dbg_mod.Error as e:
                # Can't get `next` if the main_area is corrupted.
                print(
                    message.error(
                        f"Mallocng.containing: Could not read meta_area ({e}), returning early."
                    )
                )
                return (None, None)

            # Iterate over all metas in the meta_area.
            for i in range(meta_area.nslots):
                try:
                    meta = Meta(meta_area.at_index(i))
                    if not meta.mem:
                        # Skip unused metas.
                        continue

                    group = Group(meta.mem)
                    group.set_meta(meta)

                    valid_start = group.storage - metadata_offset
                    group_end = group.addr + group.group_size

                    # Check if our address is inside one of
                    # the group's slots.
                    if valid_start <= address < group_end:
                        # Yes it is!
                        hit_group = group
                        break
                except pwndbg.dbg_mod.Error as e:
                    print(
                        message.error(
                            "Mallocng.containing: Could not read/parse meta at"
                            f" {hex(meta.addr)} ({e}), skipping it.."
                        )
                    )
                    continue

            if hit_group:
                break

            meta_area_addr = meta_area.next

        if hit_group is None:
            return (None, None)

        # Need to read memory for the .contains_group() check.
        hit_slot: Optional[Slot] = None
        # Contains extra information.
        hit_grouped_slot: Optional[GroupedSlot] = None

        if shallow:
            backup_addr = hit_group.addr
            try:
                # Go up instead of recursing.
                hit_group = hit_group.meta.root_group()
                slot_idx = (
                    address - (hit_group.storage - metadata_offset)
                ) // hit_group.meta.stride
                hit_grouped_slot = GroupedSlot(hit_group, slot_idx)
                hit_slot = Slot.from_start(hit_grouped_slot.start)
                return hit_grouped_slot, hit_slot
            except pwndbg.dbg_mod.Error as e:
                print(
                    message.error(
                        "Mallocng.containing: Failed reading memory while traversing"
                        f" parent groups to satisfy shallow=True.\n{e}.\n"
                        f"The initial match was for group @ {backup_addr}.\n"
                    )
                )
                return (None, None)

        try:
            # Recursively go into deeper nested groups until we find a slot
            # which doesn't house a group.
            while hit_slot is None or hit_slot.contains_group():
                valid_start = hit_group.storage - metadata_offset

                if address < valid_start:
                    # Bleh, the address is in the group's header
                    # (or the first slot's start header). What to do?
                    if hit_slot is not None:
                        # If we are already in some slot, just return
                        # that slot since we can't look any deeper.
                        break
                    # We are in no slot i.e. we are in the header of a
                    # top level group (either mmap()ed or donated).
                    # We could return *some* information to the callee
                    # but alas, let's be technically correct.
                    return (None, None)

                # Calculate the correct inner slot.
                slot_idx = (address - valid_start) // hit_group.meta.stride

                hit_grouped_slot = GroupedSlot(hit_group, slot_idx)
                hit_slot = Slot.from_start(hit_grouped_slot.start)

                # If the slot is not allocated, we know that we for sure can't
                # recurse deeper.
                if hit_grouped_slot.slot_state != SlotState.ALLOCATED:
                    break

                # Maybe there is a group inside this slot!
                hit_group = Group(hit_slot.p)

            return hit_grouped_slot, hit_slot

        except pwndbg.dbg_mod.Error as e:
            print(
                message.error(
                    "Mallocng.containing: Failed reading memory while traversing"
                    f" nested groups: {e}.\nReturning last valid slot."
                )
            )
            # Could be None.
            return hit_grouped_slot, hit_slot

    @override
    def containing(self, address: int, metadata: bool = False, shallow: bool = False) -> int:
        """
        Same as find_slot() but returns only the `start` address of the slot, or zero
        if no slot is found.
        """
        found, _ = self.find_slot(address, metadata, shallow)
        if found is None:
            return 0
        else:
            return found.start


mallocng = Mallocng()
