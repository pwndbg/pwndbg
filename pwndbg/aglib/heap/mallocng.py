"""
Implements handling of musl's allocator mallocng.
https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng
"""

from __future__ import annotations

from typing import List
from typing import Optional
from typing import Tuple

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory as memory
import pwndbg.aglib.typeinfo
import pwndbg.color.message as message

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
        # Alignment offsets it by 0x4
        self.slots: int = self.addr + 0x18

        self.load()

    def load(self):
        ptrsize = pwndbg.aglib.arch.ptrsize
        uint64size = pwndbg.aglib.typeinfo.uint64.sizeof
        endian = pwndbg.aglib.arch.endian

        data: bytearray = memory.read(self.addr, 0x14)

        cur_offset = 0
        self.check = int.from_bytes(
            data[cur_offset : (cur_offset + uint64size)], endian, signed=False
        )
        cur_offset += uint64size
        self.next = pwndbg.aglib.arch.unpack(data[cur_offset : (cur_offset + ptrsize)])
        cur_offset += ptrsize
        self.nslots = int.from_bytes(
            data[cur_offset : (cur_offset + int_size())], endian, signed=True
        )
        cur_offset += int_size()

        assert cur_offset == 0x14


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

        # We will always load() since we read this object
        # only once - there is no performance benefit to lazy
        # evaluation.
        self.load()

    def load(self):
        ptrsize = pwndbg.aglib.arch.ptrsize
        size_tsize = pwndbg.aglib.typeinfo.size_t.sizeof
        unsignedsize = pwndbg.aglib.typeinfo.uint.sizeof
        uint8size = pwndbg.aglib.typeinfo.uint8.sizeof
        endian = pwndbg.aglib.arch.endian

        # sizeof(__malloc_context) gives 0x3A0 when it doesn't have the
        # pagesize field (the usual case). We will read 0x3B0 in case it does.
        data: bytearray = memory.read(self.addr, 0x3B0)

        cur_offset = 0
        self.secret = pwndbg.aglib.arch.unpack(data[cur_offset : (cur_offset + ptrsize)])
        cur_offset += ptrsize

        # We will read `int` bytes past the `secret`. The `init_done` field can only contain
        # values 0 and 1, so if we get that we know the struct doesn't have the pagesize field.
        # If it contains a value > 1 it must be describing a page size.
        something = int.from_bytes(
            data[cur_offset : (cur_offset + int_size())], endian, signed=True
        )
        self.has_pagesize_field = something > 1

        if self.has_pagesize_field:
            self.pagesize = int.from_bytes(
                data[cur_offset : (cur_offset + size_tsize)], endian, signed=False
            )
            cur_offset += size_tsize

            self.init_done = int.from_bytes(
                data[cur_offset : (cur_offset + int_size())], endian, signed=True
            )
            cur_offset += int_size()
        else:
            self.init_done = something
            cur_offset += int_size()

        self.mmap_counter = int.from_bytes(
            data[cur_offset : (cur_offset + unsignedsize)], endian, signed=False
        )
        cur_offset += unsignedsize
        self.free_meta_head = int.from_bytes(
            data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
        )
        cur_offset += ptrsize
        self.avail_meta = int.from_bytes(
            data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
        )
        cur_offset += ptrsize
        self.avail_meta_count = int.from_bytes(
            data[cur_offset : (cur_offset + size_tsize)], endian, signed=False
        )
        cur_offset += size_tsize
        self.avail_meta_area_count = int.from_bytes(
            data[cur_offset : (cur_offset + size_tsize)], endian, signed=False
        )
        cur_offset += size_tsize
        self.meta_alloc_shift = int.from_bytes(
            data[cur_offset : (cur_offset + size_tsize)], endian, signed=False
        )
        cur_offset += size_tsize
        self.meta_area_head = int.from_bytes(
            data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
        )
        cur_offset += ptrsize
        self.meta_area_tail = int.from_bytes(
            data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
        )
        cur_offset += ptrsize
        self.avail_meta_areas = int.from_bytes(
            data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
        )
        cur_offset += ptrsize

        assert len(size_classes) == 48

        for i in range(len(size_classes)):
            cur_active = int.from_bytes(
                data[cur_offset : (cur_offset + ptrsize)], endian, signed=False
            )
            cur_offset += ptrsize
            self.active.append(cur_active)

        for i in range(len(size_classes)):
            cur_usage = int.from_bytes(
                data[cur_offset : (cur_offset + size_tsize)], endian, signed=False
            )
            cur_offset += size_tsize
            self.usage_by_class.append(cur_usage)

        for i in range(32):
            cur_seq = int.from_bytes(
                data[cur_offset : (cur_offset + uint8size)], endian, signed=False
            )
            cur_offset += uint8size
            self.unmap_seq.append(cur_seq)

        for i in range(32):
            cur_bounce = int.from_bytes(
                data[cur_offset : (cur_offset + uint8size)], endian, signed=False
            )
            cur_offset += uint8size
            self.bounces.append(cur_bounce)

        self.seq = int.from_bytes(data[cur_offset : (cur_offset + uint8size)], endian, signed=False)
        cur_offset += uint8size

        # Adjust for alignment
        cur_offset += ptrsize - uint8size

        self.brk = int.from_bytes(data[cur_offset : (cur_offset + ptrsize)], endian, signed=False)
        cur_offset += ptrsize

        assert cur_offset == (0x3B0 if self.has_pagesize_field else 0x3A0)


class Mallocng:
    """
    Tracks the allocator state.

    By leveraging the __malloc_context symbol.

    Attributes:
        ctx_addr: Address of the __malloc_context object.
        ctx: Object representing __malloc_context.
        secret: The secret the allocator uses for security checks.
    """

    ctx: int
    secret: int

    def __init__(self):
        self.ctx_addr: int = 0
        self.ctx: Optional[MallocContext] = None
        self.has_debug_syms: bool = False
        self.secret: int = 0
        self.hope: bool = True

        self.set_ctx_addr()

        if self.ctx_addr and self.hope:
            self.ctx = MallocContext(self.ctx_addr)

    def set_ctx_addr(self):
        """
        Find where the __malloc_context global symbol is. Try using debug information,
        but if it isn't available try using a heuristic.
        """
        self.ctx_addr = pwndbg.aglib.symbol.lookup_symbol_addr("__malloc_context")
        if self.ctx_addr is not None:
            self.has_debug_syms = True
            self.secret = memory.read_pointer_width(self.ctx_addr)
            return

        # No debug information :(
        self.has_debug_syms = False

        # We will find the __malloc_context object by searching memory for
        # the secret.
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L50
        # Extract the secret first.
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/glue.h#L49
        at_random = int(pwndbg.auxv.get()["AT_RANDOM"])
        self.secret = memory.read_pointer_width(at_random + 8)

        secret_matches = list(
            pwndbg.search.search(
                pwndbg.aglib.arch.pack(self.secret), executable=False, writable=True, aligned=8
            )
        )

        # There are going to be multiple matches. We don't
        # want those on the stack (actual AT_RANDOM) or heap
        # (structures copying the secret). We want it either from the libc.so
        # mapping (if musl is dynamically linked) or the executable's
        # mapping (if musl is statically linked).
        possible: List[Tuple[int, str]] = []
        for sm in secret_matches:
            mapping_name = pwndbg.aglib.vmmap.find(sm).objfile
            if "[stack" in mapping_name or "[heap" in mapping_name:
                continue

            possible.append((sm, mapping_name))

        if not possible:
            print(message.error("Couldn't find __malloc_context, even with heuristic."))
            print(message.error("Musl mallocng commands will not work."))
            self.ctx_addr = 0
            self.hope = False
            return

        if pwndbg.dbg.selected_inferior().is_dynamically_linked():
            for addr, mapname in possible:
                if mapname.endswith("libc.so"):
                    self.ctx_addr = addr
                    return

            for addr, mapname in possible:
                if mapname.contains("libc"):
                    self.ctx_addr = addr
                    return

            print(message.warn("Couldn't find __malloc_context in a 'libc' mapping,"))
            print(message.warn(f"using mapping '{possible[0][1]}',"))
            print(
                message.warn(
                    "and assuming __malloc_context is at "
                    f"{pwndbg.color.memory.get(possible[0][0])}."
                )
            )
            print(message.warn("The heap commands may be unreliable."))
        else:
            # Statically linked.
            # TODO: We should find the Executable Object in the mappings
            # and use that to determine which match is correct. Not sure
            # how to do that though so fall through for now.
            pass

        self.ctx_addr = possible[0][0]

    def libc_has_debug_syms(self) -> bool:
        return self.has_debug_syms
