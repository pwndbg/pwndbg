from __future__ import annotations

from typing import NamedTuple

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo

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


class _RtreeGeom(NamedTuple):
    """Radix-tree geometry actually used by the inferior's jemalloc (see
    :func:`_load_rtree_geom`)."""

    levels: list[tuple[int, int]]  # (bits, cumbits) per level; len == tree height
    nhib: int  # high insignificant address bits (= 64 - LG_VADDR)
    compact: bool  # whether a leaf packs the edata pointer + metadata into one word
    node_sizeof: int  # stride of an interior-node element
    leaf_sizeof: int  # stride of a leaf element


def _default_rtree_geom() -> _RtreeGeom:
    """Geometry assuming LG_VADDR == 48 (4-level paging). Used only as a fallback
    when jemalloc's actual layout cannot be read from the target."""
    levels = [(lvl["bits"], lvl["cumbits"]) for lvl in rtree_levels[RTREE_HEIGHT - 1]]
    ptr_sizeof = 1 << LG_SIZEOF_PTR
    return _RtreeGeom(levels, RTREE_NHIB, True, ptr_sizeof, ptr_sizeof)


def _load_rtree_geom() -> _RtreeGeom:
    """Read jemalloc's rtree geometry from the target instead of assuming it.

    jemalloc derives the tree's height, per-level bit splits and leaf layout from
    LG_VADDR at build time -- 48 on 4-level-paging hosts, 57 on 5-level (LA57) -- and
    the two layouts are incompatible, so assuming 48 misreads a 57-bit build (the
    #3615 flake: it depended on the CI build host's CPU). Falls back to the 48-bit
    layout if jemalloc's ``rtree_levels`` table can't be read.

    Height, per-level bit splits and the root array all derive from LG_VADDR in
    jemalloc rtree.h (RTREE_NHIB = 64 - LG_VADDR, RTREE_NSB, RTREE_HEIGHT, rtree_levels):
    https://github.com/jemalloc/jemalloc/blob/81034ce1f1373e37dc865038e1bc8eeecf559ce8/include/jemalloc/internal/rtree.h#L21-L38
    """
    try:
        frame = pwndbg.dbg.selected_frame()
        ctx = frame or pwndbg.dbg.selected_inferior()
        height = int(ctx.evaluate_expression("sizeof(rtree_levels)")) // int(
            ctx.evaluate_expression("sizeof(rtree_levels[0])")
        )
        levels = [
            (
                int(ctx.evaluate_expression(f"rtree_levels[{i}].bits")),
                int(ctx.evaluate_expression(f"rtree_levels[{i}].cumbits")),
            )
            for i in range(height)
        ]
        nhib = levels[0][1] - levels[0][0]
        node_sizeof = int(ctx.evaluate_expression("sizeof(struct rtree_node_elm_s)"))
        leaf_sizeof = int(ctx.evaluate_expression("sizeof(struct rtree_leaf_elm_s)"))
        # jemalloc uses a "compact" leaf -- the edata pointer packed with its metadata
        # into one word (le_bits) -- only when enough high bits are free, i.e.
        # RTREE_NHIB (= 64 - LG_VADDR) >= LG_CEIL(SC_NSIZES); otherwise the leaf is a
        # plain edata pointer plus a separate metadata word ({le_edata, le_metadata},
        # twice the size). We read the actual struct size rather than recompute that.
        # jemalloc rtree.h (RTREE_LEAF_COMPACT condition + struct rtree_leaf_elm_s):
        # https://github.com/jemalloc/jemalloc/blob/81034ce1f1373e37dc865038e1bc8eeecf559ce8/include/jemalloc/internal/rtree.h#L37-L88
        compact = leaf_sizeof == (1 << LG_SIZEOF_PTR)
        return _RtreeGeom(levels, nhib, compact, node_sizeof, leaf_sizeof)
    except (pwndbg.dbg_mod.Error, ValueError, TypeError):
        return _default_rtree_geom()


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

        rtree_s = pwndbg.aglib.typeinfo.load("struct rtree_s")
        if rtree_s is None:
            raise pwndbg.dbg_mod.Error("rtree_s type not found")

        # self._Value = pwndbg.aglib.memory.poi(emap_s, self._addr)

        # self._Value = pwndbg.aglib.memory.fetch_struct_as_dictionary(
        #     "rtree_s", self._addr, include_only_fields={"root"}
        # )
        # pwndbg.aglib.memory
        self._Value = pwndbg.aglib.memory.get_typed_pointer_value("struct rtree_s", self._addr)

        self._extents = None
        self._geom = _load_rtree_geom()

    @staticmethod
    def get_rtree() -> RTree:
        addr = pwndbg.aglib.symbol.lookup_symbol_addr("je_arena_emap_global")
        if addr is None:
            raise pwndbg.dbg_mod.Error("Required je_arena_emap_global symbol not found")
        return RTree(addr)

    @property
    def root(self):
        return self._Value["root"]

    def __subkey(self, key: int, level: int) -> int:
        """
        Return a portion of the key that is used to find the node/leaf in the rtree at a specific level.
        Source: https://github.com/jemalloc/jemalloc/blob/5b72ac098abce464add567869d082f2097bd59a2/include/jemalloc/internal/rtree.h#L161
        """

        ptrbits = 1 << (LG_SIZEOF_PTR + 3)
        maskbits, cumbits = self._geom.levels[level - 1]
        shiftbits = ptrbits - cumbits

        return (key >> shiftbits) & ((1 << maskbits) - 1)

    def __decode_leaf(self, raw: int) -> int:
        """Extract the edata pointer from the first word of a rtree leaf element.

        On compact leaves that word is ``le_bits`` (the edata pointer packed with
        szind/slab metadata); on non-compact leaves it is ``le_edata`` (a plain
        edata pointer with its metadata kept in a separate word). Either way the
        edata pointer lives at offset 0, so a single word read covers both.
        """
        if raw == 0:
            return 0
        if self._geom.compact:
            ls = (raw << self._geom.nhib) & ((2**64) - 1)
            return ((ls >> self._geom.nhib) >> 1) << 1
        return raw & ~1

    @staticmethod
    def __alignment_addr2base(addr, alignment=64):
        return addr - (addr - (addr & (~(alignment - 1))))

    def lookup_hard(self, key: int):
        """
        Lookup the key in the rtree and return the extent that owns it.

        Jemalloc stores each mapped page's owning extent in the rtree, keyed by the
        page address. We walk every level of the tree: interior levels hold child
        pointers to the next level, the final level holds leaf elements that encode
        the extent (edata) pointer. The number of levels, the per-level bit splits
        and the leaf layout all come from the target (see :func:`_load_rtree_geom`).

        Credits: 盏一's jegdb
        https://web.archive.org/web/20221114090949/https://github.com/hidva/hidva.github.io/blob/dev/_drafts/jegdb.py
        """
        geom = self._geom
        height = len(geom.levels)

        # Interior levels store a child pointer at offset 0 of each node element;
        # leaf elements store the (packed or plain) edata pointer at offset 0.
        cur = int(self.root.address)
        ptr = 0
        for level in range(1, height + 1):
            subkey = self.__subkey(key, level)
            if level < height:
                cur = int(pwndbg.aglib.memory.u64(cur + subkey * geom.node_sizeof))
                if cur == 0:
                    return None
            else:
                raw = int(pwndbg.aglib.memory.u64(cur + subkey * geom.leaf_sizeof))
                ptr = self.__decode_leaf(raw)

        if ptr == 0:
            return None

        extent = Extent(ptr)
        if extent.size == 0:
            aligned = RTree.__alignment_addr2base(ptr)
            extent_tmp = Extent(aligned)
            if extent_tmp.size != 0:
                return extent_tmp

        return extent

    @property
    def extents(self):
        # NOTE: Generating whole extents list is slow as it requires parsing whole rtree

        if self._extents is None:  # TODO: handling cache on extents changes
            self._extents = []
            try:
                geom = self._geom
                height = len(geom.levels)
                ptr_size = 1 << LG_SIZEOF_PTR

                # Collect every extent pointer stored in the tree's leaves. Each
                # node/leaf array is contiguous, so read a whole level in one shot
                # rather than element by element -- a level can have tens of
                # thousands of slots, and one extent spans many (de-duplicated next).
                leaf_ptrs: list[int] = []

                def walk(base_addr: int, level: int) -> None:
                    bits = geom.levels[level - 1][0]
                    n = 1 << bits
                    stride = geom.node_sizeof if level < height else geom.leaf_sizeof
                    data = pwndbg.aglib.memory.read(base_addr, n * stride)
                    for i in range(n):
                        word = int.from_bytes(data[i * stride : i * stride + ptr_size], "little")
                        if word == 0:
                            continue
                        if level < height:
                            # interior node: word is the child pointer
                            walk(word, level + 1)
                        else:
                            ptr = self.__decode_leaf(word)
                            if ptr != 0:
                                leaf_ptrs.append(ptr)

                walk(int(self.root.address), 1)

                last_addr = None
                extent_addresses = []
                for ptr in leaf_ptrs:
                    if ptr == last_addr:
                        continue
                    last_addr = ptr

                    extent = Extent(ptr)

                    if extent.extent_address in extent_addresses:
                        continue

                    extent_addresses.append(extent.extent_address)

                    # during initializations, addresses may get some alignment
                    # lets check if size makes sense, otherwise do page alignment and check if again
                    # TODO: better way to do this
                    extent_tmp = extent
                    if extent.size == 0:
                        aligned = RTree.__alignment_addr2base(int(ptr))
                        extent_tmp = Extent(aligned)
                        if extent_tmp.size != 0:
                            self._extents.append(extent_tmp)
                            continue

                    self._extents.append(extent_tmp)

            except pwndbg.dbg_mod.Error:
                pass

        return self._extents


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
        self._Value = pwndbg.aglib.memory.get_typed_pointer_value("struct edata_s", self._addr)

        self._bitfields = None

    @property
    def size(self):
        """
        May be larger in case of large size class allocation when cache_oblivious is enabled.
        """
        # return self._Value["e_size_esn"]
        return (int(self._Value["e_size_esn"]) >> LG_PAGE) << LG_PAGE

    @property
    def extent_address(self) -> int:
        """
        Address of the extent data structure (not the actual memory).
        """
        return self._addr

    @property
    def allocated_address(self) -> int:
        """
        Starting address of allocated memory
        cache-oblivious large allocation alignment:
            When a large class allocation is made, jemalloc selects the closest size class that can fit the request and allocates that size + 4 KiB (0x1000).
            However, the pointer returned to user is randomized between the 'base' and 'base + 4 KiB' (0x1000) range.
            Source code: https://github.com/jemalloc/jemalloc/blob/a25b9b8ba91881964be3083db349991bbbbf1661/include/jemalloc/internal/arena_inlines_b.h#L505
        """
        return int(self._Value["e_addr"])

    @property
    def bsize(self) -> int:
        return int(self._Value["e_bsize"])

    @property
    def bits(self) -> int:
        return int(self._Value["e_bits"])

    @property
    def bitfields(self) -> dict[str, int]:
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
    def state_name(self) -> str:
        state_mapping = ["Active", "Dirty", "Muzzy", "Retained"]

        return state_mapping[self.bitfields["state"]]

    @property
    def has_slab(self) -> bool:
        """
        Returns True if the extent is used for small size classes.
        Reference for size in Table 1 at https://jemalloc.net/jemalloc.3.html
        At time of writing, allocations <= 0x3800 are considered as small allocations and has slabs.
        """
        return self.bitfields["slab"] != 0

    @property
    def is_free(self) -> bool:
        """
        Returns True if the extent is free.
        """

    @property
    def pai(self) -> str:
        """
        Page Allocator Interface
        """
        if self.bitfields["pai"] == 0:
            return "PAC"  # Page for extent
        return "HPA"  # Huge Page
