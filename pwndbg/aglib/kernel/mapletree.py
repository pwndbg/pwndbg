from __future__ import annotations

from collections.abc import Generator

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.dbg_mod


class MapleTree:
    def __init__(self, mm: int | pwndbg.dbg_mod.Value) -> None:
        self.mm = mm

    def maple_tree_parse(self) -> Generator[int, None, None]:
        # taken from bata24/gef
        ptrsize = pwndbg.aglib.arch.ptrsize

        MT_FLAGS_HEIGHT_MASK = 0x7C
        MT_FLAGS_HEIGHT_OFFSET = 0x02
        MAPLE_NODE_TYPE_SHIFT = 0x03
        MAPLE_NODE_TYPE_MASK = 0x0F
        MAPLE_NODE_POINTER_MASK = 0xFF
        MAPLE_DENSE = 0
        MAPLE_LEAF_64 = 1
        MAPLE_RANGE_64 = 2
        MAPLE_ARANGE_64 = 3
        MAPLE_NODE_SLOTS = 31
        MAPLE_RANGE64_SLOTS = 16
        MAPLE_ARANGE64_SLOTS = 10
        MAPLE_ALLOC_SLOTS = MAPLE_NODE_SLOTS - 1
        maple_range_64_offset_slot = ptrsize * MAPLE_RANGE64_SLOTS
        maple_arange_64_offset_slot = ptrsize * MAPLE_ARANGE64_SLOTS
        maple_alloc_offset_slot = ptrsize * 2

        kversion = pwndbg.aglib.kernel.krelease()
        mm = int(self.mm)
        ma_flags = ma_root = None
        for i in range(0x20):
            off = i * ptrsize
            val = pwndbg.aglib.memory.read_pointer_width(mm + off)
            if pwndbg.aglib.memory.is_kernel(val) and val & 0xFF in (0x1E, 0x0E):
                ma_root = pwndbg.aglib.memory.read_pointer_width(mm + off)
                if kversion and kversion < (6, 6):
                    ma_flags = pwndbg.aglib.memory.uint(mm + off + ptrsize)
                else:
                    ma_flags = pwndbg.aglib.memory.uint(mm + off - 4)
                    if ma_flags == 0:
                        ma_flags = pwndbg.aglib.memory.uint(mm + off - 12)
                break
        else:
            return
        max_depth = (ma_flags & MT_FLAGS_HEIGHT_MASK) >> MT_FLAGS_HEIGHT_OFFSET

        seen = set()

        def __parse_node(entry: int, depth: int):
            if entry in seen:
                return
            if depth > max_depth:
                return
            seen.add(entry)

            pointer = entry & ~(MAPLE_NODE_POINTER_MASK)
            node_type = (entry >> MAPLE_NODE_TYPE_SHIFT) & MAPLE_NODE_TYPE_MASK
            if node_type == MAPLE_DENSE:
                slots = pointer + maple_alloc_offset_slot
                for i in range(MAPLE_ALLOC_SLOTS):
                    slot = pwndbg.aglib.memory.read_pointer_width(slots + i * ptrsize)
                    if slot & ~MAPLE_ALLOC_SLOTS != 0:
                        if pwndbg.aglib.memory.is_kernel(slot):
                            yield slot
            elif node_type == MAPLE_LEAF_64:
                slots = pointer + maple_range_64_offset_slot
                for i in range(MAPLE_RANGE64_SLOTS):
                    slot = pwndbg.aglib.memory.read_pointer_width(slots + i * ptrsize)
                    if slot & ~MAPLE_ALLOC_SLOTS != 0:
                        if pwndbg.aglib.memory.is_kernel(slot):
                            yield slot
            elif node_type == MAPLE_RANGE_64:
                slots = pointer + maple_range_64_offset_slot
                for i in range(MAPLE_RANGE64_SLOTS):
                    slot = pwndbg.aglib.memory.read_pointer_width(slots + i * ptrsize)
                    if slot & ~MAPLE_ALLOC_SLOTS != 0:
                        if pwndbg.aglib.memory.is_kernel(slot):
                            yield from __parse_node(slot, depth + 1)
            elif node_type == MAPLE_ARANGE_64:
                slots = pointer + maple_arange_64_offset_slot
                for i in range(MAPLE_ARANGE64_SLOTS):
                    slot = pwndbg.aglib.memory.read_pointer_width(slots + i * ptrsize)
                    if slot & ~MAPLE_ALLOC_SLOTS != 0:
                        if pwndbg.aglib.memory.is_kernel(slot):
                            yield from __parse_node(slot, depth + 1)

        yield from __parse_node(ma_root, 1)
