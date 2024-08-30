from __future__ import annotations

import gdb

import pwndbg.gdblib.info
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo

# adapted from jemalloc source 5.3.0
LG_VADDR = 48
LG_PAGE = 12
# https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/internal/jemalloc_internal_types.h#L42
MALLOCX_ARENA_BITS = 12
# https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/jemalloc_defs.h.in#L51
LG_SIZEOF_PTR = 3

RTREE_NHIB = (1 << (LG_SIZEOF_PTR + 3)) - LG_VADDR  # Number of high insignificant bits
RTREE_NLIB = LG_PAGE  # Number of low insigificant bits
RTREE_NSB = LG_VADDR - RTREE_NLIB  # Number of significant bits

# Number of levels in radix tree
if RTREE_NSB <= 10:
    RTREE_HEIGHT = 1
elif RTREE_NSB <= 36:
    RTREE_HEIGHT = 2
elif RTREE_NSB <= 52:
    RTREE_HEIGHT = 3
else:
    raise ValueError("Unsupported number of significant virtual address bits")


# TODO: RTREE_LEAF_COMPACT should be enabled otherwise rtree_leaf_elm_s would change

# TODO: Move to relevant place
# https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/internal/edata.h#L145


def mask(current_field_width, current_field_shift):
    return ((1 << current_field_width) - 1) << current_field_shift


# For size class related explanation and calculations, refer to https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/internal/sc.h#L8

LG_QUANTUM = 4  # LG_QUANTUM ensures correct platform alignment and necessary to ensure we never return improperly aligned memory

SC_LG_TINY_MIN = 3
SC_NTINY = (
    LG_QUANTUM - SC_LG_TINY_MIN
)  # Number of tiny size classes for alloations smaller than (1 << LG_QUANTUM)

# Size classes
SC_LG_NGROUP = 2  # Number of size classes group
SC_NGROUP = (
    1 << SC_LG_NGROUP
)  # Number of size classes in each group, equally spaced in the range, so that * each one covers allocations for base / SC_NGROUP possible allocation sizes
SC_NPSEUDO = SC_NGROUP
SC_PTR_BITS = (1 << LG_SIZEOF_PTR) * 8
SC_LG_BASE_MAX = SC_PTR_BITS - 2
SC_LG_FIRST_REGULAR_BASE = LG_QUANTUM + SC_LG_NGROUP
SC_NREGULAR = SC_NGROUP * (SC_LG_BASE_MAX - SC_LG_FIRST_REGULAR_BASE + 1) - 1

SC_NSIZES = SC_NTINY + SC_NPSEUDO + SC_NREGULAR

SC_LG_SLAB_MAXREGS = LG_PAGE - SC_LG_TINY_MIN


# Source: https://github.com/jemalloc/jemalloc/blob/dev/include/jemalloc/internal/bit_util.h#L400-L419
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

# In RTree, Each level distinguishes a certain number of bits from the key, which helps in narrowing down the search space
# bits: how many bits have been used at that particular level (Number of key bits distinguished by this level)
# cumbits: how many bits in total have been used up to that level (Cumulative number of key bits distinguished by traversing to corresponding tree level)
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
    """
    RTree is used by jemalloc to keep track of extents that are allocated by jemalloc.
    Since extent data is not stored in a doubly linked list, rtree is used to find the extent belonging to a pointer that is being freed.
    Implementation of rtree is similar to Linux Radix tree: https://lwn.net/Articles/175432/
    """

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
            if addr is None:
                return None

        except gdb.MemoryError:
            return None

        return RTree(addr)

    @property
    def root(self):
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
        """
        Return a portion of the key that is used to find the node/leaf in the rtree at a specific level.
        Source: https://github.com/jemalloc/jemalloc/blob/5b72ac098abce464add567869d082f2097bd59a2/include/jemalloc/internal/rtree.h#L161
        """

        ptrbits = 1 << (LG_SIZEOF_PTR + 3)
        cumbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["cumbits"]
        shiftbits = ptrbits - cumbits
        maskbits = rtree_levels[RTREE_HEIGHT - 1][level - 1]["bits"]
        mask = (1 << maskbits) - 1

        return (key >> shiftbits) & mask

    def __alignment_addr2base(addr, alignment=64):
        return addr - (addr - (addr & (~(alignment - 1))))

    def lookup_hard(self, key):
        """
        Lookup the key in the rtree and return the value.

        How it works:
        - Jemalloc stores the extent address in the rtree as a node and to find a specific node we need a address key.
        """
        rtree_node_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_node_elm_s")
        rtree_leaf_elm_s = pwndbg.gdblib.typeinfo.load("struct rtree_leaf_elm_s")

        # Credits: 盏一's jegdb

        # For subkey 0
        subkey = self.__subkey(key, 1)

        addr = int(self.root.address) + subkey * rtree_node_elm_s.sizeof
        node = pwndbg.gdblib.memory.fetch_struct_as_dictionary("rtree_node_elm_s", addr)
        
        # on node element, child contains the bits with which we can find another node or leaf element
        if int(node["child"]["repr"]) == 0:
            return None

        # For subkey 1
        subkey = self.__subkey(key, 2)
        addr = int(node["child"]["repr"]) + subkey * rtree_leaf_elm_s.sizeof
        leaf = pwndbg.gdblib.memory.fetch_struct_as_dictionary("rtree_leaf_elm_s", addr)

        # On leaf element, le_bits contains the virtual memory address bits so we can use it to find the extent address
        if leaf["le_bits"]["repr"] == 0:
            return None

        val = int(leaf["le_bits"]["repr"])

        # In this function, we are trying to find the extent address given the address of memory block
        # that this extent is managing (which is represented by edata->e_addr in the extent structure)

        # e_addr is 64 bits but
        # e_addr is also page (4096) aligned which means last 12 bits are zero and therefore unused
        # In rtree, each layer can be accessed using bits 0-16, 17-33 and 34-51
        # When height of rtree is 3, level 1 can be accessed using bits 0-16, and so on for level 2 and 3
        # When the height is 2, 0-15 bits are unused and level 1 can be accessed using bits 16-33 and level 2 using 34-51

        ls = (val << RTREE_NHIB) & ((2**64) - 1)
        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

        if ptr == 0:
            return None

        return Extent(ptr)

    @property
    def extents(self):
        # NOTE: Generating whole extents list is slow as it requires parsing whole rtree

        if self._extents is None:  # TODO: handling cache on extents changes
            self._extents = []
            try:
                root = self.root
                last_addr = None
                extent_addresses = []

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
                    # print(hex(leaf0))

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

                        # print("leaf: ", hex(leaf_address))

                        # print(j, leaf)
                        val = int(leaf["le_bits"]["repr"])

                        if val == 0:
                            # return None
                            continue

                        ls = (val << RTREE_NHIB) & ((2**64) - 1)
                        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

                        if ptr == 0 or ptr == last_addr:
                            continue

                        last_addr = ptr

                        extent = Extent(ptr)

                        if extent.extent_address in extent_addresses:
                            continue

                        extent_addresses.append(extent.extent_address)

                        # during initializations, addresses may get some alignment
                        # lets check if size makes sense, otherwise do page alignment and check if again
                        # TODO: better way to do this
                        if extent.size == 0:
                            ptr = RTree.__alignment_addr2base(int(ptr))
                            extent_tmp = Extent(ptr)
                            if extent_tmp.size == 0:
                                self._extents.append(extent)

                        self._extents.append(extent_tmp)

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
    """
    Concept of extent (edata) is similar to chunk in glibc malloc but allocation algorithm differs a lot.
    - Extents are used to manage memory blocks (including jemalloc metadata) where extents sizes can vary but each block is always a multiple of the page size.
    - jemalloc will either allocate one large class request or multiple small class request (called slab) depending on request size.
    - Unlike chunks in glibc malloc, extents are not doubly linked list but are managed using rtree.
    - This tree is mostly used during deallocation to find the extent belonging to a pointer that is being freed.
    - Extents are also not stored as a header structure but externally (therefore extent metadata and actually mapped data may be very far apart).
    """

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
        Address of the extent data structure (not the actual memory).
        """
        return self._addr

    @property
    def allocated_address(self):
        """
        Starting address of allocated memory
        cache-oblivious large allocation alignment:
            When a large class allocation is made, jemalloc selects the closest size class that can fit the request and allocates that size + 4 KiB (0x1000).
            However, the pointer returned to user is randomized between the 'base' and 'base + 4 KiB' (0x1000) range.
            Source code: https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/internal/arena_inlines_b.h#L505
        """
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
    def state_name(self):
        state_mapping = ["Active", "Dirty", "Muzzy", "Retained"]

        return state_mapping[self.bitfields["state"]]

    @property
    def has_slab(self):
        """
        Returns True if the extent is used for small size classes.
        Reference for size in Table 1 at https://jemalloc.net/jemalloc.3.html
        At time of writing, allocations <= 0x3800 are considered as small allocations and has slabs.
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
