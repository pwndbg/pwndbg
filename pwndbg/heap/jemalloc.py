from __future__ import annotations

import gdb

import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo

RTREE_HEIGHT = 2
# adapted from jemalloc source 5.3.0
LG_VADDR = 48
LG_PAGE = 12
RTREE_NLIB = LG_PAGE
# jemalloc/include/jemalloc/internal/jemalloc_internal_types.h
MALLOCX_ARENA_BITS = 12
# obj/include/jemalloc/jemalloc.h
LG_SIZEOF_PTR = 3

RTREE_NSB = LG_VADDR - RTREE_NLIB
RTREE_NHIB = (1 << (LG_SIZEOF_PTR + 3)) - LG_VADDR


EXTENT_BITS_ARENA_WIDTH = MALLOCX_ARENA_BITS
EXTENT_BITS_ARENA_SHIFT = 0
EXTENT_BITS_ARENA_MASK = MASK(EXTENT_BITS_ARENA_WIDTH, EXTENT_BITS_ARENA_SHIFT)

EXTENT_BITS_SLAB_WIDTH = 1
EXTENT_BITS_SLAB_SHIFT = EXTENT_BITS_ARENA_WIDTH + EXTENT_BITS_ARENA_SHIFT
EXTENT_BITS_SLAB_MASK = MASK(EXTENT_BITS_SLAB_WIDTH, EXTENT_BITS_SLAB_SHIFT)


# TODO: Move all rtree operations to different class / helper class
# TODO: Figure out where to move this definition
rtree_levels = [
    # for height == 1
    [{"bits": RTREE_NSB, "cumbits": RTREE_NHIB + RTREE_NSB}],
    # for height == 2
    [
        {"bits": RTREE_NSB // 2, "cumbits": RTREE_NHIB + RTREE_NSB // 2},
        {"bits": RTREE_NSB // 2 + RTREE_NSB % 2, "cumbits": RTREE_NHIB + RTREE_NSB},
    ],
    # for height == 3
    [
        {"bits": RTREE_NSB // 3, "cumbits": RTREE_NHIB + RTREE_NSB // 3},
        {
            "bits": RTREE_NSB // 3 + RTREE_NSB % 3 // 2,
            "cumbits": RTREE_NHIB + RTREE_NSB // 3 * 2 + RTREE_NSB % 3 // 2,
        },
        {
            "bits": RTREE_NSB // 3 + RTREE_NSB % 3 - RTREE_NSB % 3 // 2,
            "cumbits": RTREE_NHIB + RTREE_NSB,
        },
    ],
]


class RTree:
    def __init__(self, addr: int) -> None:
        self._addr = addr

        # gdb value with struct emap_s
        emap_s = pwndbg.gdblib.typeinfo.load("struct emap_s")
        self._gdbValue = pwndbg.gdblib.memory.poi(emap_s, self._addr)

    @staticmethod
    def get_rtree() -> RTree:
        try:
            addr = pwndbg.gdblib.info.address("je_arena_emap_global")
            if addr is None:
                return None

        except gdb.MemoryError:
            return None

        return RTree(addr)

    @property
    def rtree(self):
        return self._gdbValue["rtree"]

    @property
    def root(self):
        return self.rtree["root"]

    # from include/jemalloc/internal/rtree.h
    def __subkey(self, key, level):
        ptrbits = 1 << (LG_SIZEOF_PTR + 3)
        cumbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["cumbits"]
        shiftbits = ptrbits - cumbits
        maskbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["bits"]
        mask = (1 << maskbits) - 1
        return (key >> shiftbits) & mask

    def lookup_hard(self, key):
        """
        Lookup the key in the rtree and return the value.
        """
        rtree_node_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_node_elm_s")
        rtree_leaf_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_leaf_elm_s")

        # Credits: 盏一's jegdb

        # For subkey 0
        subkey = self.__subkey(key, 1)
        addr = int(self.root.address) + subkey * rtree_node_elm_s.sizeof
        print(int(self.root.address), subkey, rtree_node_elm_s.sizeof)
        print("addr:", addr)
        node = pwndbg.gdblib.memory.poi(rtree_node_elm_s, addr)
        if node["child"]["repr"] == 0:
            return None

        # For subkey 1
        subkey = self.__subkey(key, 2)
        addr = int(node["child"]["repr"]) + subkey * rtree_leaf_elm_s.sizeof
        leaf = pwndbg.gdblib.memory.poi(rtree_leaf_elm_s, addr)
        if leaf["le_bits"]["repr"] == 0:
            return None

        val = int(leaf["le_bits"]["repr"])
        ls = (val << RTREE_NHIB) & ((2**64) - 1)
        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

        if ptr == 0:
            return None

        return Extent(ptr)


class Arena:
    def __init__(self, addr: int) -> None:
        self._addr = addr

        # gdb value with arena_t structure
        arena_s = pwndbg.gdblib.typeinfo.load("struct arena_s")
        self._gdbValue = pwndbg.gdblib.memory.poi(arena_s, self._addr)

        self._nbins = None

        self._bins = None
        self._extents = None

    @property
    def bins(self):
        if self._bins is None:
            self._bins = []
            try:
                # TODO: verify this variable
                self._nbins = gdb.parse_and_eval("nbins_total").cast(
                    gdb.lookup_type("unsigned int")
                )

                bins_addr = int(self._gdbValue["bins"].address)
                bin_s = pwndbg.gdblib.typeinfo.load("struct bin_s")
                for i in range(self._nbins):
                    current_bin_addr = int(bins_addr) + i * bin_s.sizeof
                    bin = pwndbg.gdblib.memory.poi(bin_s, current_bin_addr)
                    self._bins.append(bin)

            except gdb.MemoryError:
                pass

        return self._bins

    @property
    def extents(self):
        # NOTE: Generating whole extents list is slow as it requires parsing whole rtree

        if self._extents is None:  # TODO: handling cache on extents changes
            self._extents = []
            try:
                rtree = gdb.lookup_global_symbol("je_arena_emap_global").value()
                root = rtree["rtree"]["root"]

                rtree_node_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_node_elm_s")
                rtree_leaf_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_leaf_elm_s")

                max_subkeys = 1 << rtree_levels[RTREE_HEIGHT - 1][0]["bits"]
                print("max_subkeys: ", max_subkeys)

                for i in range(max_subkeys):
                    node = int(root.address) + i * rtree_node_elm_s.sizeof
                    node = pwndbg.gdblib.memory.poi(rtree_node_elm_s, node)
                    if node["child"]["repr"] == 0:
                        continue
                    leaf0 = node["child"]["repr"]

                    # level 1
                    for j in range(max_subkeys):
                        leaf = int(leaf0) + j * rtree_leaf_elm_s.sizeof
                        leaf = pwndbg.gdblib.memory.poi(rtree_leaf_elm_s, leaf)
                        if leaf["le_bits"]["repr"] == 0:
                            continue

                        val = int(leaf["le_bits"]["repr"])

                        ls = (val << RTREE_NHIB) & ((2**64) - 1)
                        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

                        if ptr == 0:
                            continue

                        extent = Extent(ptr)
                        self._extents.append(extent)

            except gdb.MemoryError:
                pass

        return self._extents


class Extent:
    def __init__(self, addr: int) -> None:
        self._addr = addr

        # gdb value with edata_t structure
        edata_s = pwndbg.gdblib.typeinfo.load("struct edata_s")
        self._gdbValue = pwndbg.gdblib.memory.poi(edata_s, self._addr)

    @property
    def size(self):
        return self._gdbValue["e_size_esn"]

    @property
    def address(self):
        """
        Returns the address of the memory location the extent is pointing to.
        """
        return self._gdbValue["e_addr"]

    @property
    def bsize(self):
        return self._gdbValue["e_bsize"]

    @property
    def bits(self):
        return self._gdbValue["e_bits"]

    # boolean
    @property
    def has_slab(self):
        """
        Returns True if the extent is used for small size classes.
        """
        return ((self.e_bits & EXTENT_BITS_SLAB_MASK) >> EXTENT_BITS_SLAB_SHIFT) != 0
