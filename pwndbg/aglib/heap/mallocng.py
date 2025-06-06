"""
Implements handling of musl's allocator mallocng.
https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng
"""

from __future__ import annotations

from typing import List

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory as memory
import pwndbg.aglib.typeinfo as typeinfo

# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L14
# Slot granularity.
UNIT = 16
# Size of in-band metadata.
IB = 4

# https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/malloc.c#L12
# Describes the possible sizes a slot can be. These are `/ UNIT`.
size_classes: List[int] = [
    1,
    2,
    3,
    4,
    5,
    6,
    7,
    8,
    9,
    10,
    12,
    15,
    18,
    20,
    25,
    31,
    36,
    42,
    50,
    63,
    72,
    84,
    102,
    127,
    146,
    170,
    204,
    255,
    292,
    340,
    409,
    511,
    584,
    682,
    818,
    1023,
    1169,
    1364,
    1637,
    2047,
    2340,
    2730,
    3276,
    4095,
    4680,
    5460,
    6552,
    8191,
]

# Shorthand
INT_SIZE = typeinfo.sint.sizeof


class Group:
    """
    A group is an array of slots.

    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L17
    """

    def __init__(self, addr: int) -> None:
        self.addr = addr

        self._meta = None
        self._active_idx = None

    @property
    def meta(self) -> Meta:
        if self._meta is None:
            self._meta = Meta(memory.read_pointer_width(self.addr))

        return self._meta

    @property
    def active_idx(self) -> int:
        if self._active_idx is None:
            self._active_idx = memory.u8(self.addr + pwndbg.aglib.arch.ptrsize) & 0b11111

        return self._active_idx

    @property
    def storage(self) -> int:
        return self.addr + UNIT


class Slot:
    """
    The "unit of allocation" (analogous to glibc's "chunk").
    There is no struct in the source code that describes it.

    The class operates under the assumption the address given
    to it is valid and readable.
    """

    def __init__(self, p: int) -> None:
        # The start of user memory. It may
        # not be the actual start of the slot.
        self.p = p
        self._offset = None
        self._idx = None
        # Not exactly sure what this is.
        self._check4 = None

        self._group = None
        self._meta = None
        self._reserved = None

    @property
    def check4(self) -> int:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L134
        if self._check4 is None:
            self._check4 = memory.u8(self.p - 4)

        return self._check4

    @property
    def offset(self) -> int:
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
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L133
        if self._idx is None:
            self._idx = memory.u8(self.p - 3) & 31

        return self._idx

    @property
    def group(self) -> Group:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L139
        if self._group is None:
            self._group = Group(self.p - UNIT * self.offset - UNIT)

        return self._group

    @property
    def meta(self) -> Meta:
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
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/free.c#L109
        return self.start + self.meta.stride - IB

    @property
    def reserved(self) -> int:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L161
        # Lots of asserts here..
        if self._reserved is None:
            self._reserved = memory.u8(self.p - 3) >> 5
            if self._reserved == 5:
                self._reserved = memory.u32(self.end - 4)

        return self._reserved

    @property
    def nominal_size(self) -> int:
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L159
        return self.end - self.reserved - self.p

    @property
    def user_size(self) -> int:
        return self.nominal_size


class Meta:
    """
    The metadata of a group.
    https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L24
    """

    def __init__(self, addr: int) -> None:
        self.addr = addr

        self._prev = self._next = None
        self._mem = None
        self._avail_mask = self._freed_mask = None
        self._last_idx = None
        self._freeable = None
        self._sizeclass = None
        self._maplen = None

        self._stride = None

    @property
    def prev(self) -> int:
        if self._prev is None:
            self._prev = memory.read_pointer_width(self.addr)

        return self._prev

    @property
    def next(self) -> int:
        if self._next is None:
            self._next = memory.read_pointer_width(self.addr + pwndbg.aglib.arch.ptrsize)

        return self._next

    @property
    def mem(self) -> int:
        if self._mem is None:
            self._mem = memory.read_pointer_width(self.addr + pwndbg.aglib.arch.ptrsize * 2)

        return self._mem

    @property
    def avail_mask(self) -> int:
        if self._avail_mask is None:
            self._avail_mask = memory.sint(self.addr + pwndbg.aglib.arch.ptrsize * 3)

        return self._avail_mask

    @property
    def freed_mask(self) -> int:
        if self._freed_mask is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + INT_SIZE
            self._freed_mask = memory.sint(self.addr + offset)

        return self._freed_mask

    @property
    def last_idx(self) -> int:
        if self._last_idx is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + INT_SIZE * 2
            self._last_idx = memory.u8(self.addr + offset) & 0b11111

        return self._last_idx

    @property
    def freeable(self) -> int:
        if self._freeable is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + INT_SIZE * 2
            self._freeable = (memory.u8(self.addr + offset) >> 5) & 1

        return self._freeable

    @property
    def sizeclass(self) -> int:
        if self._sizeclass is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + INT_SIZE * 2
            self._sizeclass = (memory.u16(self.addr + offset) >> 6) & 0b111111

        return self._sizeclass

    @property
    def maplen(self) -> int:
        if self._maplen is None:
            offset = pwndbg.aglib.arch.ptrsize * 3 + INT_SIZE * 2 + 1
            sz_bits = pwndbg.aglib.arch.ptrsize * 8 - 12
            self._maplen = (memory.u64(self.addr + offset) >> 4) & ((1 << sz_bits) - 1)

        return self._maplen

    @property
    def stride(self):
        # https://elixir.bootlin.com/musl/v1.2.5/source/src/malloc/mallocng/meta.h#L175
        if self._stride is None:
            if not self.last_idx and self.maplen:
                self._stride = self.maplen * 4096 - UNIT
            else:
                self._stride = UNIT * size_classes[self.sizeclass]

        return self._stride


class MetaArea:
    def __init__(self, addr: int) -> None:
        self.addr = addr


class Mallocng:
    pass
