from __future__ import annotations

import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo

RTREE_HEIGHT = 2
# adapted from jemalloc source 5.3.0
LG_VADDR = 48
LG_PAGE = 12
RTREE_NLIB = LG_PAGE
# obj/include/jemalloc/jemalloc.h
LG_SIZEOF_PTR = 3

RTREE_NSB = LG_VADDR - RTREE_NLIB
RTREE_NHIB = (1 << (LG_SIZEOF_PTR + 3)) - LG_VADDR


class Arena:
    def __init__(self, addr: int) -> None:
        self._addr = addr

        # gdb value with arena_t structure
        arena_s = pwndbg.gdblib.typeinfo.load("struct arena_s")
        self._gdbValue = pwndbg.gdblib.memory.poi(arena_s, self._addr)

        self._nbins = None

        # TODO: Perhaps create bins, extents class and only store needed/useful information, remove mutexes, etc.
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

        if self._extents is None:
            self._extents = []
            try:
                edata_s = pwndbg.gdblib.typeinfo.load("struct edata_s")

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

                        # https://hidva.com/assets/jegdb.py
                        ls = (val << RTREE_NHIB) & ((2**64) - 1)
                        ptr = ((ls >> RTREE_NHIB) >> 1) << 1

                        if ptr == 0:
                            continue

                        extent = pwndbg.gdblib.memory.poi(edata_s, ptr)

                        # print(extent)
                        print("edata address: ", hex(ptr))
                        print("e_bits: ", extent["e_bits"])
                        print("e_addr: ", extent["e_addr"])
                        # size
                        print("e_size_esn: ", extent["e_size_esn"])
                        print("e_bsize: ", extent["e_bsize"])

                        self._extents.append(extent)

            except gdb.MemoryError:
                pass

        return self._extents
