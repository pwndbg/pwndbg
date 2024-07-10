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


# TODO: Move to relevant place
# include/jemalloc/internal/edata.h


def mask(current_field_width, current_field_shift):
    return ((1 << current_field_width) - 1) << current_field_shift


LG_QUANTUM = 4  # TODO: lookup value acc to architecture from include/jemalloc/internal/quantum.h (currently set for arch64)
SC_LG_TINY_MIN = 3
SC_NTINY = LG_QUANTUM - SC_LG_TINY_MIN

SC_LG_NGROUP = 2
SC_NGROUP = 1 << SC_LG_NGROUP
SC_NPSEUDO = SC_NGROUP
SC_PTR_BITS = (1 << LG_SIZEOF_PTR) * 8
SC_LG_BASE_MAX = SC_PTR_BITS - 2
SC_LG_FIRST_REGULAR_BASE = LG_QUANTUM + SC_LG_NGROUP
SC_NREGULAR = SC_NGROUP * (SC_LG_BASE_MAX - SC_LG_FIRST_REGULAR_BASE + 1) - 1

SC_NSIZES = SC_NTINY + SC_NPSEUDO + SC_NREGULAR

SC_LG_SLAB_MAXREGS = LG_PAGE - SC_LG_TINY_MIN


def lg_floor_1(x):
    return 0


def lg_floor_2(x):
    return lg_floor_1(x) if x < (1 << 1) else 1 + lg_floor_1(x >> 1)


def lg_floor_4(x):
    return lg_floor_2(x) if x < (1 << 2) else 2 + lg_floor_2(x >> 2)


def lg_floor_8(x):
    return lg_floor_4(x) if x < (1 << 4) else 4 + lg_floor_4(x >> 4)


def lg_floor_16(x):
    return lg_floor_8(x) if x < (1 << 8) else 8 + lg_floor_8(x >> 8)


def lg_floor_32(x):
    return lg_floor_16(x) if x < (1 << 16) else 16 + lg_floor_16(x >> 16)


def lg_floor_64(x):
    return lg_floor_32(x) if x < (1 << 32) else 32 + lg_floor_32(x >> 32)


def lg_floor(x):
    return lg_floor_32(x) if LG_SIZEOF_PTR == 2 else lg_floor_64(x)


def lg_ceil(x):
    return lg_floor(x) + (0 if (x & (x - 1)) == 0 else 1)


# Arena width and mask definitions
EDATA_BITS_ARENA_WIDTH = MALLOCX_ARENA_BITS
EDATA_BITS_ARENA_SHIFT = 0
EDATA_BITS_ARENA_MASK = mask(EDATA_BITS_ARENA_WIDTH, EDATA_BITS_ARENA_SHIFT)

# Slab width and mask definitions
EDATA_BITS_SLAB_WIDTH = 1
EDATA_BITS_SLAB_SHIFT = EDATA_BITS_ARENA_WIDTH + EDATA_BITS_ARENA_SHIFT
EDATA_BITS_SLAB_MASK = mask(EDATA_BITS_SLAB_WIDTH, EDATA_BITS_SLAB_SHIFT)

# Committed width and mask definitions
EDATA_BITS_COMMITTED_WIDTH = 1
EDATA_BITS_COMMITTED_SHIFT = EDATA_BITS_SLAB_WIDTH + EDATA_BITS_SLAB_SHIFT
EDATA_BITS_COMMITTED_MASK = mask(EDATA_BITS_COMMITTED_WIDTH, EDATA_BITS_COMMITTED_SHIFT)

# PAI width and mask definitions
EDATA_BITS_PAI_WIDTH = 1
EDATA_BITS_PAI_SHIFT = EDATA_BITS_COMMITTED_WIDTH + EDATA_BITS_COMMITTED_SHIFT
EDATA_BITS_PAI_MASK = mask(EDATA_BITS_PAI_WIDTH, EDATA_BITS_PAI_SHIFT)

# Zeroed width and mask definitions
EDATA_BITS_ZEROED_WIDTH = 1
EDATA_BITS_ZEROED_SHIFT = EDATA_BITS_PAI_WIDTH + EDATA_BITS_PAI_SHIFT
EDATA_BITS_ZEROED_MASK = mask(EDATA_BITS_ZEROED_WIDTH, EDATA_BITS_ZEROED_SHIFT)

# Guarded width and mask definitions
EDATA_BITS_GUARDED_WIDTH = 1
EDATA_BITS_GUARDED_SHIFT = EDATA_BITS_ZEROED_WIDTH + EDATA_BITS_ZEROED_SHIFT
EDATA_BITS_GUARDED_MASK = mask(EDATA_BITS_GUARDED_WIDTH, EDATA_BITS_GUARDED_SHIFT)

# State width and mask definitions
EDATA_BITS_STATE_WIDTH = 3
EDATA_BITS_STATE_SHIFT = EDATA_BITS_GUARDED_WIDTH + EDATA_BITS_GUARDED_SHIFT
EDATA_BITS_STATE_MASK = mask(EDATA_BITS_STATE_WIDTH, EDATA_BITS_STATE_SHIFT)

EDATA_BITS_SZIND_WIDTH = lg_ceil(SC_NSIZES)
EDATA_BITS_SZIND_SHIFT = EDATA_BITS_STATE_WIDTH + EDATA_BITS_STATE_SHIFT
EDATA_BITS_SZIND_MASK = mask(EDATA_BITS_SZIND_WIDTH, EDATA_BITS_SZIND_SHIFT)

# Nfree width and mask definitions
EDATA_BITS_NFREE_WIDTH = SC_LG_SLAB_MAXREGS + 1
EDATA_BITS_NFREE_SHIFT = EDATA_BITS_SZIND_WIDTH + EDATA_BITS_SZIND_SHIFT
EDATA_BITS_NFREE_MASK = mask(EDATA_BITS_NFREE_WIDTH, EDATA_BITS_NFREE_SHIFT)

# Binshard width and mask definitions
EDATA_BITS_BINSHARD_WIDTH = 6
EDATA_BITS_BINSHARD_SHIFT = EDATA_BITS_NFREE_WIDTH + EDATA_BITS_NFREE_SHIFT
EDATA_BITS_BINSHARD_MASK = mask(EDATA_BITS_BINSHARD_WIDTH, EDATA_BITS_BINSHARD_SHIFT)

# Is head width and mask definitions
EDATA_BITS_IS_HEAD_WIDTH = 1
EDATA_BITS_IS_HEAD_SHIFT = EDATA_BITS_BINSHARD_WIDTH + EDATA_BITS_BINSHARD_SHIFT
EDATA_BITS_IS_HEAD_MASK = mask(EDATA_BITS_IS_HEAD_WIDTH, EDATA_BITS_IS_HEAD_SHIFT)

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
    # TODO: Check rtee_ctx cache in
    # tsd_nominal_tsds.qlh_first.cant_access_tsd_items_directly_use_a_getter_or_setter_rtree_ctx.cache
    def __init__(self, addr: int) -> None:
        self._addr = addr

        rtree_s = pwndbg.gdblib.typeinfo.load("struct rtree_s")
        # self._Value = pwndbg.gdblib.memory.poi(emap_s, self._addr)

        # self._Value = pwndbg.gdblib.memory.fetch_struct_as_dictionary(
        #     "rtree_s", self._addr, include_only_fields={"root"}
        # )
        self._Value = gdb.Value(self._addr).cast(rtree_s.pointer()).dereference()

        self._extents = None

    @staticmethod
    def get_rtree() -> RTree:
        try:
            addr = pwndbg.gdblib.info.address("je_arena_emap_global")
            print(addr)
            if addr is None:
                return None

        except gdb.MemoryError:
            return None

        return RTree(addr)

    @property
    def root(self):
        # return self.rtree["root"]
        return self._Value["root"]

    # from include/jemalloc/internal/rtree.h
    # converted implementation of rtree_leafkey
    def __rtree_leaf_maskbits(self, level):
        ptrbits = 1 << (LG_SIZEOF_PTR + 3)
        # print("ptrbits: ", ptrbits, bin(ptrbits))
        cumbits = (
            rtree_levels[RTREE_HEIGHT - 1][level - 1]["cumbits"]
            - rtree_levels[RTREE_HEIGHT - 1][level - 1]["bits"]
        )
        # print("cumbits: ", cumbits, bin(cumbits))
        return ptrbits - cumbits

    # Can be used to lookup key quickly in cache
    def __rtree_leafkey(self, key, level):
        mask = ~((1 << self.__rtree_leaf_maskbits(level)) - 1)
        # print("mask: ", mask, bin(mask))
        return key & mask

    def __subkey(self, key, level):
        # print()
        # print("KEY: ", key, bin(key))
        ptrbits = 1 << (LG_SIZEOF_PTR + 3)
        # print("ptrbits: ", ptrbits, bin(ptrbits))
        cumbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["cumbits"]
        # print("cumbits: ", cumbits, bin(cumbits))
        shiftbits = ptrbits - cumbits
        # print("shiftbits: ", shiftbits, bin(shiftbits))
        maskbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["bits"]
        # print("maskbits: ", maskbits, bin(maskbits))
        mask = (1 << maskbits) - 1
        # print("mask: ", mask, bin(mask))
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
        # print("original: ", subkey)
        # subkey = self.__rtree_leafkey(key, 1)
        # print("new1: ", subkey)
        # subkey = self.__rtree_leafkey(key, 2)
        # print("new2: ", subkey)

        addr = int(self.root.address) + subkey * rtree_node_elm_s.sizeof
        # node = pwndbg.gdblib.memory.poi(rtree_node_elm_s, addr)
        node = pwndbg.gdblib.memory.fetch_struct_as_dictionary("rtree_node_elm_s", addr)

        if node["child"]["repr"] == 0:
            return None

        # For subkey 1
        subkey = self.__subkey(key, 2)
        addr = int(node["child"]["repr"]) + subkey * rtree_leaf_elm_s.sizeof
        # leaf = pwndbg.gdblib.memory.poi(rtree_leaf_elm_s, addr)
        leaf = pwndbg.gdblib.memory.fetch_struct_as_dictionary("rtree_leaf_elm_s", addr)
        if leaf["le_bits"]["repr"] == 0:
            return None

        val = int(leaf["le_bits"]["repr"])
        ls = (val << RTREE_NHIB) & ((2**64) - 1)
        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

        if ptr == 0:
            return None

        return Extent(ptr)

    def test_parse(self):
        pass

    @property
    def extents(self):
        # NOTE: Generating whole extents list is slow as it requires parsing whole rtree

        if self._extents is None:  # TODO: handling cache on extents changes
            self._extents = []
            try:
                root = self.root
                last_addr = None

                rtree_node_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_node_elm_s")
                rtree_leaf_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_leaf_elm_s")

                max_subkeys = 1 << rtree_levels[RTREE_HEIGHT - 1][0]["bits"]
                # print("max_subkeys: ", max_subkeys)

                for i in range(max_subkeys):
                    node_address = int(root.address) + i * rtree_node_elm_s.sizeof
                    # node = pwndbg.gdblib.memory.poi(rtree_node_elm_s, node)
                    fetched_struct = pwndbg.gdblib.memory.get_typed_pointer_value(
                        rtree_node_elm_s, node_address
                    )
                    node = pwndbg.gdblib.memory.pack_struct_into_dictionary(fetched_struct)

                    if node["child"]["repr"] == 0:
                        continue
                    leaf0 = node["child"]["repr"]

                    # print("leaf0: ", leaf0)

                    # level 1
                    for j in range(max_subkeys):
                        leaf_address = int(leaf0) + j * rtree_leaf_elm_s.sizeof
                        # leaf = pwndbg.gdblib.memory.poi(rtree_leaf_elm_s, leaf)
                        fetched_struct = pwndbg.gdblib.memory.get_typed_pointer_value(
                            rtree_leaf_elm_s, leaf_address
                        )
                        leaf = pwndbg.gdblib.memory.pack_struct_into_dictionary(fetched_struct)

                        if leaf["le_bits"]["repr"] == 0:
                            continue

                        # print(j, leaf)
                        val = int(leaf["le_bits"]["repr"])

                        if val == 0:
                            return None

                        ls = (val << RTREE_NHIB) & ((2**64) - 1)
                        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

                        if ptr == 0 or ptr == last_addr:
                            continue

                        last_addr = ptr

                        extent = Extent(ptr)
                        self._extents.append(extent)
                        # print("extent addr: ", hex(extent.extent_address))
                        # print("allocated addr: ", hex(extent.allocated_address))
                        # print()

            except gdb.MemoryError:
                pass

        return self._extents


class Arena:
    """
    Some notes:
    - Huge allocation should not come from arena 0
    """

    def __init__(self, addr: int) -> None:
        self._addr = addr

        self._Value = pwndbg.gdblib.memory.fetch_struct_as_dictionary("arena_s", self._addr)

        self._nbins = None
        self._slabs = None

    @property
    def slabs(self):
        if self._bins is None:
            self._bins = []
            try:
                # TODO: verify this variable
                self._nbins = gdb.parse_and_eval("nbins_total").cast(
                    gdb.lookup_type("unsigned int")
                )

                bins_addr = int(self._Value["bins"].address)
                bin_s = pwndbg.gdblib.typeinfo.load("struct bin_s")
                for i in range(self._nbins):
                    current_bin_addr = int(bins_addr) + i * bin_s.sizeof
                    bin = pwndbg.gdblib.memory.poi(bin_s, current_bin_addr)
                    self._slabs.append(bin)

            except gdb.MemoryError:
                pass

        return self._slabs


class Extent:
    def __init__(self, addr: int) -> None:
        self._addr = addr

        # fetch_struct_as_dictionary does not support union currently
        edata_s = pwndbg.gdblib.typeinfo.load("struct edata_s")
        self._Value = gdb.Value(self._addr).cast(edata_s.pointer()).dereference()

        self._bitfields = None

    @property
    def size(self):
        """
        May be larger in case of large size class allocation when cache_oblivious is enabled.
        """
        # return self._Value["e_size_esn"]
        return (int(self._Value["e_size_esn"]) >> LG_PAGE) << LG_PAGE

    @property
    def extent_address(self):
        """
        Returns the address of the memory location the extent is pointing to.
        """
        return self._addr

    # Address of allocated memory address
    @property
    def allocated_address(self):
        return self._Value["e_addr"]

    @property
    def bsize(self):
        return self._Value["e_bsize"]

    @property
    def bits(self):
        return self._Value["e_bits"]

    @property
    def bitfields(self):
        """
        Extract bitfields

        arena_ind: Arena from which this extent came, or all 1 bits if unassociated.
        slab: The slab flag indicates whether the extent is used for a slab of small regions. This helps differentiate small size classes, and it indicates whether interior pointers can be looked up via iealloc().
        committed: The committed flag indicates whether physical memory is committed to the extent, whether explicitly or implicitly as on a system that overcommits and satisfies physical memory needs on demand via soft page faults.
        pai: The pai flag is an extent_pai_t.
        zeroed: The zeroed flag is used by extent recycling code to track whether memory is zero-filled.
        guarded: The guarded flag is used by the sanitizer to track whether the extent has page guards around it.
        state: The state flag is an extent_state_t.
        szind: The szind flag indicates usable size class index for allocations residing in this extent, regardless of whether the extent is a slab. Extent size and usable size often differ even for non-slabs, either due to sz_large_pad or promotion of sampled small regions.
        nfree: Number of free regions in slab.
        bin_shard: The shard of the bin from which this extent came.
        """

        if self._bitfields is None:
            self._bitfields = {
                "arena_ind": (self.bits & EDATA_BITS_ARENA_MASK) >> EDATA_BITS_ARENA_SHIFT,
                "slab": (self.bits & EDATA_BITS_SLAB_MASK) >> EDATA_BITS_SLAB_SHIFT,
                "committed": (self.bits & EDATA_BITS_COMMITTED_MASK) >> EDATA_BITS_COMMITTED_SHIFT,
                "pai": (self.bits & EDATA_BITS_PAI_MASK) >> EDATA_BITS_PAI_SHIFT,
                "zeroed": (self.bits & EDATA_BITS_ZEROED_MASK) >> EDATA_BITS_ZEROED_SHIFT,
                "guarded": (self.bits & EDATA_BITS_GUARDED_MASK) >> EDATA_BITS_GUARDED_SHIFT,
                "state": (self.bits & EDATA_BITS_STATE_MASK) >> EDATA_BITS_STATE_SHIFT,
                "szind": (self.bits & EDATA_BITS_SZIND_MASK) >> EDATA_BITS_SZIND_SHIFT,
                "nfree": (self.bits & EDATA_BITS_NFREE_MASK) >> EDATA_BITS_NFREE_SHIFT,
                "bin_shard": (self.bits & EDATA_BITS_BINSHARD_MASK) >> EDATA_BITS_BINSHARD_SHIFT,
            }

        return self._bitfields

    @property
    def has_slab(self):
        """
        Returns True if the extent is used for small size classes.
        """
        return self.bitfields["slab"] != 0

    @property
    def is_free(self):
        """
        Returns True if the extent is free.
        """
        pass

    @property
    def pai(self):
        """
        Page Allocator Interface
        """
        if self.bitfields["pai"] == 0:
            return "PAC"  # Page for extent
        return "HPA"  # Huge Page
