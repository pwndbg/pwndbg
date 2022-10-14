import importlib
from collections import OrderedDict

import gdb

import pwndbg.color.memory as M
import pwndbg.disasm
import pwndbg.gdblib.config
import pwndbg.gdblib.events
import pwndbg.gdblib.symbol
import pwndbg.gdblib.tls
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap
import pwndbg.glibc
import pwndbg.search
from pwndbg.color import message
from pwndbg.constants import ptmalloc
from pwndbg.heap import heap_chain_limit

# See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l30
# and https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l869
# 1 Mb (x86) or 64 Mb (x64)
HEAP_MAX_SIZE = 1024 * 1024 if pwndbg.gdblib.arch.ptrsize == 4 else 2 * 4 * 1024 * 1024 * 8


def heap_for_ptr(ptr):
    """Round a pointer to a chunk down to find its corresponding heap_info
    struct, the pointer must point inside a heap which does not belong to
    the main arena.
    """
    return ptr & ~(HEAP_MAX_SIZE - 1)


class Chunk:
    __slots__ = (
        "_gdbValue",
        "address",
        "_prev_size",
        "_size",
        "_real_size",
        "_flags",
        "_non_main_arena",
        "_is_mmapped",
        "_prev_inuse",
        "_fd",
        "_bk",
        "_fd_nextsize",
        "_bk_nextsize",
        "_arena",
        "_is_top_chunk",
    )

    def __init__(self, addr, arena=None):
        if isinstance(pwndbg.heap.current.malloc_chunk, gdb.Type):
            self._gdbValue = pwndbg.gdblib.memory.poi(pwndbg.heap.current.malloc_chunk, addr)
        else:
            self._gdbValue = pwndbg.heap.current.malloc_chunk(addr)
        self.address = int(self._gdbValue.address)
        self._prev_size = None
        self._size = None
        self._real_size = None
        self._flags = None
        self._non_main_arena = None
        self._is_mmapped = None
        self._prev_inuse = None
        self._fd = None
        self._bk = None
        self._fd_nextsize = None
        self._bk_nextsize = None
        self._arena = arena
        self._is_top_chunk = None

    # Some chunk fields were renamed in GLIBC 2.25 master branch.
    def __match_renamed_field(self, field):
        field_renames = {
            "size": ["size", "mchunk_size"],
            "prev_size": ["prev_size", "mchunk_prev_size"],
        }

        for field_name in field_renames[field]:
            if gdb.types.has_field(self._gdbValue.type, field_name):
                return field_name

        raise ValueError(f"Chunk field name did not match any of {field_renames[field]}.")

    @property
    def prev_size(self):
        if self._prev_size is None:
            try:
                self._prev_size = int(self._gdbValue[self.__match_renamed_field("prev_size")])
            except gdb.MemoryError:
                pass

        return self._prev_size

    @property
    def size(self):
        if self._size is None:
            try:
                self._size = int(self._gdbValue[self.__match_renamed_field("size")])
            except gdb.MemoryError:
                pass

        return self._size

    @property
    def real_size(self):
        if self._real_size is None:
            try:
                self._real_size = int(
                    self._gdbValue[self.__match_renamed_field("size")]
                    & ~(ptmalloc.NON_MAIN_ARENA | ptmalloc.IS_MMAPPED | ptmalloc.PREV_INUSE)
                )
            except gdb.MemoryError:
                pass

        return self._real_size

    @property
    def flags(self):
        if self._flags is None:
            if self.size is not None:
                self._flags = {
                    "non_main_arena": self.non_main_arena,
                    "is_mmapped": self.is_mmapped,
                    "prev_inuse": self.prev_inuse,
                }

        return self._flags

    @property
    def non_main_arena(self):
        if self._non_main_arena is None:
            sz = self.size
            if sz is not None:
                self._non_main_arena = bool(sz & ptmalloc.NON_MAIN_ARENA)

        return self._non_main_arena

    @property
    def is_mmapped(self):
        if self._is_mmapped is None:
            sz = self.size
            if sz is not None:
                self._is_mmapped = bool(sz & ptmalloc.IS_MMAPPED)

        return self._is_mmapped

    @property
    def prev_inuse(self):
        if self._prev_inuse is None:
            sz = self.size
            if sz is not None:
                self._prev_inuse = bool(sz & ptmalloc.PREV_INUSE)

        return self._prev_inuse

    @property
    def fd(self):
        if self._fd is None:
            try:
                self._fd = int(self._gdbValue["fd"])
            except gdb.MemoryError:
                pass

        return self._fd

    @property
    def bk(self):
        if self._bk is None:
            try:
                self._bk = int(self._gdbValue["bk"])
            except gdb.MemoryError:
                pass

        return self._bk

    @property
    def fd_nextsize(self):
        if self._fd_nextsize is None:
            try:
                self._fd_nextsize = int(self._gdbValue["fd_nextsize"])
            except gdb.MemoryError:
                pass

        return self._fd_nextsize

    @property
    def bk_nextsize(self):
        if self._bk_nextsize is None:
            try:
                self._bk_nextsize = int(self._gdbValue["bk_nextsize"])
            except gdb.MemoryError:
                pass

        return self._bk_nextsize

    @property
    def arena(self):
        if self._arena is None:
            try:
                ar_ptr = pwndbg.heap.current.get_heap(self.address)["ar_ptr"]
                ar_ptr.fetch_lazy()
            except Exception:
                ar_ptr = None
            if ar_ptr is not None and ar_ptr in (ar.address for ar in pwndbg.heap.current.arenas):
                self._arena = Arena(ar_ptr)
            else:
                self._arena = Arena(pwndbg.heap.current.main_arena.address)

        return self._arena

    @property
    def is_top_chunk(self):
        if self._is_top_chunk is None:
            ar = self.arena
            if ar is not None and self.address == ar.top:
                self._is_top_chunk = True
            else:
                self._is_top_chunk = False

        return self._is_top_chunk


class Arena:
    __slots__ = ("_gdbValue", "address", "is_main_arena", "_top", "heaps")

    def __init__(self, addr, heaps=None):
        if isinstance(pwndbg.heap.current.malloc_state, gdb.Type):
            self._gdbValue = pwndbg.gdblib.memory.poi(pwndbg.heap.current.malloc_state, addr)
        else:
            self._gdbValue = pwndbg.heap.current.malloc_state(addr)
        self.address = int(self._gdbValue.address)
        self.is_main_arena = self.address == pwndbg.heap.current.main_arena.address
        self._top = None
        self.heaps = heaps

    @property
    def top(self):
        if self._top is None:
            try:
                self._top = int(self._gdbValue["top"])
            except gdb.MemoryError:
                pass

        return self._top

    def __str__(self):
        prefix = "[%%%ds]    " % (pwndbg.gdblib.arch.ptrsize * 2)
        prefix_len = len(prefix % (""))
        arena_name = "main" if self.is_main_arena else hex(self.address)
        res = [message.hint(prefix % (arena_name)) + str(self.heaps[0])]
        for h in self.heaps[1:]:
            res.append(" " * prefix_len + str(h))

        return "\n".join(res)


class HeapInfo:
    def __init__(self, addr, first_chunk):
        self.addr = addr
        self.first_chunk = first_chunk

    def __str__(self):
        fmt = "[%%%ds]" % (pwndbg.gdblib.arch.ptrsize * 2)
        return message.hint(fmt % (hex(self.first_chunk))) + M.heap(
            str(pwndbg.gdblib.vmmap.find(self.addr))
        )


class Heap(pwndbg.heap.heap.BaseHeap):
    def __init__(self):
        # Global ptmalloc objects
        self._global_max_fast_addr = None
        self._global_max_fast = None
        self._main_arena_addr = None
        self._main_arena = None
        self._mp_addr = None
        self._mp = None
        # List of arenas/heaps
        self._arenas = None
        # ptmalloc cache for current thread
        self._thread_cache = None

    def can_be_resolved(self):
        raise NotImplementedError()

    @property
    def main_arena(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def arenas(self):
        arena = self.main_arena
        arenas = []
        arena_cnt = 0
        main_arena_addr = int(arena.address)
        sbrk_page = self.get_heap_boundaries().vaddr

        # Create the main_arena with a fake HeapInfo
        main_arena = Arena(main_arena_addr, [HeapInfo(sbrk_page, sbrk_page)])
        arenas.append(main_arena)

        # Iterate over all the non-main arenas
        addr = int(arena["next"])
        while addr != main_arena_addr:
            heaps = []
            arena = self.get_arena(addr)
            arena_cnt += 1

            # Get the first and last element on the heap linked list of the arena
            last_heap_addr = heap_for_ptr(int(arena["top"]))
            first_heap_addr = heap_for_ptr(addr)

            heap = self.get_heap(last_heap_addr)
            if not heap:
                print(message.error("Could not find the heap for arena %s" % hex(addr)))
                return

            # Iterate over the heaps of the arena
            haddr = last_heap_addr
            while haddr != 0:
                if haddr == first_heap_addr:
                    # The first heap has a heap_info and a malloc_state before the actual chunks
                    chunks_offset = self.heap_info.sizeof + self.malloc_state.sizeof
                else:
                    # The others just
                    chunks_offset = self.heap_info.sizeof
                heaps.append(HeapInfo(haddr, haddr + chunks_offset))

                # Name the heap mapping, so that it can be colored properly. Note that due to the way malloc is
                # optimized, a vm mapping may contain two heaps, so the numbering will not be exact.
                page = self.get_region(haddr)
                page.objfile = "[heap %d:%d]" % (arena_cnt, len(heaps))
                heap = self.get_heap(haddr)
                haddr = int(heap["prev"])

            # Add to the list of arenas and move on to the next one
            arenas.append(Arena(addr, tuple(reversed(heaps))))
            addr = int(arena["next"])

        arenas = tuple(arenas)
        self._arenas = arenas
        return arenas

    def has_tcache(self):
        raise NotImplementedError()

    @property
    def thread_cache(self):
        raise NotImplementedError()

    @property
    def mp(self):
        raise NotImplementedError()

    @property
    def global_max_fast(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def heap_info(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_chunk(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_state(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_entry(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def mallinfo(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_par(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_alignment(self):
        """Corresponds to MALLOC_ALIGNMENT in glibc malloc.c"""
        # i386 will override it to 16 when GLIBC version >= 2.26
        # See https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/i386/malloc-alignment.h#L22
        return (
            16
            if pwndbg.gdblib.arch.current == "i386" and pwndbg.glibc.get_version() >= (2, 26)
            else pwndbg.gdblib.arch.ptrsize * 2
        )

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def size_sz(self):
        """Corresponds to SIZE_SZ in glibc malloc.c"""
        return pwndbg.gdblib.arch.ptrsize

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_align_mask(self):
        """Corresponds to MALLOC_ALIGN_MASK in glibc malloc.c"""
        return self.malloc_alignment - 1

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def minsize(self):
        """Corresponds to MINSIZE in glibc malloc.c"""
        return self.min_chunk_size

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def min_chunk_size(self):
        """Corresponds to MIN_CHUNK_SIZE in glibc malloc.c"""
        return pwndbg.gdblib.arch.ptrsize * 4

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def multithreaded(self):
        """Is malloc operating within a multithreaded environment."""
        addr = pwndbg.gdblib.symbol.address("__libc_multiple_threads")
        if addr:
            return pwndbg.gdblib.memory.s32(addr) > 0
        return len(gdb.execute("info threads", to_string=True).split("\n")) > 3

    def _request2size(self, req):
        """Corresponds to request2size in glibc malloc.c"""
        if req + self.size_sz + self.malloc_align_mask < self.minsize:
            return self.minsize
        return (req + self.size_sz + self.malloc_align_mask) & ~self.malloc_align_mask

    def _spaces_table(self):
        spaces_table = (
            [pwndbg.gdblib.arch.ptrsize * 2] * 64
            + [pow(2, 6)] * 32
            + [pow(2, 9)] * 16
            + [pow(2, 12)] * 8
            + [pow(2, 15)] * 4
            + [pow(2, 18)] * 2
            + [pow(2, 21)] * 1
        )

        # There is no index 0
        spaces_table = [None] + spaces_table

        # Fix up the slop in bin spacing (part of libc - they made
        # the trade off of some slop for speed)
        # https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1356
        if pwndbg.gdblib.arch.ptrsize == 8:
            spaces_table[97] = 64
            spaces_table[98] = 448

        spaces_table[113] = 1536
        spaces_table[121] = 24576
        spaces_table[125] = 98304

        return spaces_table

    def chunk_flags(self, size):
        return (
            size & ptmalloc.PREV_INUSE,
            size & ptmalloc.IS_MMAPPED,
            size & ptmalloc.NON_MAIN_ARENA,
        )

    def chunk_key_offset(self, key):
        """Find the index of a field in the malloc_chunk struct.

        64bit example:
            prev_size == 0
            size      == 8
            fd        == 16
            bk        == 24
            ...
        """
        renames = {
            "mchunk_size": "size",
            "mchunk_prev_size": "prev_size",
        }
        val = self.malloc_chunk
        chunk_keys = [renames[key] if key in renames else key for key in val.keys()]
        try:
            return chunk_keys.index(key) * pwndbg.gdblib.arch.ptrsize
        except Exception:
            return None

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_next_offset(self):
        return self.tcache_entry.keys().index("next") * pwndbg.gdblib.arch.ptrsize

    def get_heap(self, addr):
        raise NotImplementedError()

    def get_arena(self, arena_addr=None):
        raise NotImplementedError()

    def get_arena_for_chunk(self, addr):
        chunk = pwndbg.commands.heap.read_chunk(addr)
        _, _, nm = self.chunk_flags(chunk["size"])
        if nm:
            h = self.get_heap(addr)
            r = self.get_arena(h["ar_ptr"]) if h else None
        else:
            r = self.main_arena
        return r

    def get_tcache(self, tcache_addr=None):
        raise NotImplementedError()

    def get_heap_boundaries(self, addr=None):
        raise NotImplementedError()

    def get_region(self, addr):
        """Find the memory map containing 'addr'."""
        return pwndbg.gdblib.vmmap.find(addr)

    def fastbin_index(self, size):
        if pwndbg.gdblib.arch.ptrsize == 8:
            return (size >> 4) - 2
        else:
            return (size >> 3) - 2

    def fastbins(self, arena_addr=None):
        """Returns: chain or None"""
        arena = self.get_arena(arena_addr)

        if arena is None:
            return

        fastbinsY = arena["fastbinsY"]
        fd_offset = self.chunk_key_offset("fd")
        num_fastbins = 7
        size = pwndbg.gdblib.arch.ptrsize * 2
        safe_lnk = pwndbg.glibc.check_safe_linking()

        result = OrderedDict()
        for i in range(num_fastbins):
            size += pwndbg.gdblib.arch.ptrsize * 2
            chain = pwndbg.chain.get(
                int(fastbinsY[i]),
                offset=fd_offset,
                limit=heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result[size] = chain

        result["type"] = "fastbins"
        return result

    def tcachebins(self, tcache_addr=None):
        """Returns: tuple(chain, count) or None"""
        tcache = self.get_tcache(tcache_addr)

        if tcache is None:
            return

        counts = tcache["counts"]
        entries = tcache["entries"]

        num_tcachebins = entries.type.sizeof // entries.type.target().sizeof
        safe_lnk = pwndbg.glibc.check_safe_linking()

        def tidx2usize(idx):
            """Tcache bin index to chunk size, following tidx2usize macro in glibc malloc.c"""
            return idx * self.malloc_alignment + self.minsize - self.size_sz

        result = OrderedDict()
        for i in range(num_tcachebins):
            size = self._request2size(tidx2usize(i))
            count = int(counts[i])
            chain = pwndbg.chain.get(
                int(entries[i]),
                offset=self.tcache_next_offset,
                limit=heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result[size] = (chain, count)

        result["type"] = "tcachebins"
        return result

    def bin_at(self, index, arena_addr=None):
        """
        Modeled after glibc's bin_at function - so starts indexing from 1
        https://bazaar.launchpad.net/~ubuntu-branches/ubuntu/trusty/eglibc/trusty-security/view/head:/malloc/malloc.c#L1394

        bin_at(1) returns the unsorted bin

        Bin 1          - Unsorted BiN
        Bin 2 to 63    - Smallbins
        Bin 64 to 126  - Largebins

        Returns: tuple(chain_from_bin_fd, chain_from_bin_bk, is_chain_corrupted) or None
        """
        index = index - 1
        arena = self.get_arena(arena_addr)

        if arena is None:
            return

        normal_bins = arena["bins"]
        num_bins = normal_bins.type.sizeof // normal_bins.type.target().sizeof

        bins_base = int(normal_bins.address) - (pwndbg.gdblib.arch.ptrsize * 2)
        current_base = bins_base + (index * pwndbg.gdblib.arch.ptrsize * 2)

        front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
        fd_offset = self.chunk_key_offset("fd")
        bk_offset = self.chunk_key_offset("bk")

        is_chain_corrupted = False

        get_chain = lambda bin, offset: pwndbg.chain.get(
            int(bin),
            offset=offset,
            hard_stop=current_base,
            limit=heap_chain_limit,
            include_start=True,
        )
        chain_fd = get_chain(front, fd_offset)
        chain_bk = get_chain(back, bk_offset)

        # check if bin[index] points to itself (is empty)
        if len(chain_fd) == len(chain_bk) == 2 and chain_fd[0] == chain_bk[0]:
            chain_fd = [0]
            chain_bk = [0]

        # check if corrupted
        elif chain_fd[:-1] != chain_bk[:-2][::-1] + [chain_bk[-2]]:
            is_chain_corrupted = True

        return (chain_fd, chain_bk, is_chain_corrupted)

    def unsortedbin(self, arena_addr=None):
        chain = self.bin_at(1, arena_addr=arena_addr)
        result = OrderedDict()

        if chain is None:
            return

        result["all"] = chain

        result["type"] = "unsortedbin"
        return result

    def smallbins(self, arena_addr=None):
        size = self.min_chunk_size - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(2, 64):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        result["type"] = "smallbins"
        return result

    def largebins(self, arena_addr=None):
        size = (ptmalloc.NSMALLBINS * self.malloc_alignment) - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = OrderedDict()
        for index in range(64, 127):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            result[size] = chain

        result["type"] = "largebins"
        return result

    def largebin_index_32(self, sz):
        """Modeled on the GLIBC malloc largebin_index_32 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1414
        """
        return (
            56 + (sz >> 6)
            if (sz >> 6) <= 38
            else 91 + (sz >> 9)
            if (sz >> 9) <= 20
            else 110 + (sz >> 12)
            if (sz >> 12) <= 10
            else 119 + (sz >> 15)
            if (sz >> 15) <= 4
            else 124 + (sz >> 18)
            if (sz >> 18) <= 2
            else 126
        )

    def largebin_index_64(self, sz):
        """Modeled on the GLIBC malloc largebin_index_64 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1433
        """
        return (
            48 + (sz >> 6)
            if (sz >> 6) <= 48
            else 91 + (sz >> 9)
            if (sz >> 9) <= 20
            else 110 + (sz >> 12)
            if (sz >> 12) <= 10
            else 119 + (sz >> 15)
            if (sz >> 15) <= 4
            else 124 + (sz >> 18)
            if (sz >> 18) <= 2
            else 126
        )

    def largebin_index(self, sz):
        """Pick the appropriate largebin_index_ function for this architecture."""
        return (
            self.largebin_index_64(sz)
            if pwndbg.gdblib.arch.ptrsize == 8
            else self.largebin_index_32(sz)
        )

    def is_initialized(self):
        raise NotImplementedError()

    def is_statically_linked(self):
        out = gdb.execute("info dll", to_string=True)
        return "No shared libraries loaded at this time." in out

    def libc_has_debug_syms(self):
        """
        The `struct malloc_chunk` comes from debugging symbols and it will not be there
        for statically linked binaries
        """
        return pwndbg.gdblib.typeinfo.load("struct malloc_chunk") and pwndbg.gdblib.symbol.address(
            "global_max_fast"
        )


class DebugSymsHeap(Heap):
    can_be_resolved = Heap.libc_has_debug_syms

    @property
    def main_arena(self):
        self._main_arena_addr = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "main_arena"
        ) or pwndbg.gdblib.symbol.address("main_arena")
        if self._main_arena_addr is not None:
            self._main_arena = pwndbg.gdblib.memory.poi(self.malloc_state, self._main_arena_addr)

        return self._main_arena

    def has_tcache(self):
        return self.mp and "tcache_bins" in self.mp.type.keys() and self.mp["tcache_bins"]

    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. If it doesn't have one, use the main
        thread's tcache.
        """
        if self.has_tcache():
            tcache = self.mp["sbrk_base"] + 0x10
            if self.multithreaded:
                tcache_addr = pwndbg.gdblib.memory.pvoid(
                    pwndbg.gdblib.symbol.static_linkage_symbol_address("tcache")
                    or pwndbg.gdblib.symbol.address("tcache")
                )
                if tcache_addr != 0:
                    tcache = tcache_addr

            try:
                self._thread_cache = pwndbg.gdblib.memory.poi(self.tcache_perthread_struct, tcache)
                _ = self._thread_cache["entries"].fetch_lazy()
            except Exception as e:
                print(
                    message.error(
                        "Error fetching tcache. GDB cannot access "
                        "thread-local variables unless you compile with -lpthread."
                    )
                )
                return None

            return self._thread_cache

        print(message.warn("This version of GLIBC was not compiled with tcache support."))
        return None

    @property
    def mp(self):
        self._mp_addr = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "mp_"
        ) or pwndbg.gdblib.symbol.address("mp_")
        if self._mp_addr is not None:
            self._mp = pwndbg.gdblib.memory.poi(self.malloc_par, self._mp_addr)

        return self._mp

    @property
    def global_max_fast(self):
        self._global_max_fast_addr = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "global_max_fast"
        ) or pwndbg.gdblib.symbol.address("global_max_fast")
        if self._global_max_fast_addr is not None:
            self._global_max_fast = pwndbg.gdblib.memory.u(self._global_max_fast_addr)

        return self._global_max_fast

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def heap_info(self):
        return pwndbg.gdblib.typeinfo.load("heap_info")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_chunk(self):
        return pwndbg.gdblib.typeinfo.load("struct malloc_chunk")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_state(self):
        return pwndbg.gdblib.typeinfo.load("struct malloc_state")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        return pwndbg.gdblib.typeinfo.load("struct tcache_perthread_struct")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_entry(self):
        return pwndbg.gdblib.typeinfo.load("struct tcache_entry")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def mallinfo(self):
        return pwndbg.gdblib.typeinfo.load("struct mallinfo")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_par(self):
        return pwndbg.gdblib.typeinfo.load("struct malloc_par")

    def get_heap(self, addr):
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        try:
            r = pwndbg.gdblib.memory.poi(self.heap_info, heap_for_ptr(addr))
            r.fetch_lazy()
        except gdb.MemoryError:
            r = None

        return r

    def get_arena(self, arena_addr=None):
        """Read a malloc_state struct from the specified address, default to
        reading the current thread's arena. Return the main arena if the
        current thread is not attached to an arena.
        """
        if arena_addr is None:
            if self.multithreaded:
                arena_addr = pwndbg.gdblib.memory.u(
                    pwndbg.gdblib.symbol.static_linkage_symbol_address("thread_arena")
                    or pwndbg.gdblib.symbol.address("thread_arena")
                )
                if arena_addr > 0:
                    return pwndbg.gdblib.memory.poi(self.malloc_state, arena_addr)

            return self.main_arena

        return (
            None
            if pwndbg.gdblib.vmmap.find(arena_addr) is None
            else pwndbg.gdblib.memory.poi(self.malloc_state, arena_addr)
        )

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return pwndbg.gdblib.memory.poi(self.tcache_perthread_struct, tcache_addr)

    def get_heap_boundaries(self, addr=None):
        """Find the boundaries of the heap containing `addr`, default to the
        boundaries of the heap containing the top chunk for the thread's arena.
        """
        region = self.get_region(addr) if addr else self.get_region(self.get_arena()["top"])

        # Occasionally, the [heap] vm region and the actual start of the heap are
        # different, e.g. [heap] starts at 0x61f000 but mp_.sbrk_base is 0x620000.
        # Return an adjusted Page object if this is the case.
        page = pwndbg.lib.memory.Page(0, 0, 0, 0)
        sbrk_base = int(self.mp["sbrk_base"])
        if region == self.get_region(sbrk_base):
            if sbrk_base != region.vaddr:
                page.vaddr = sbrk_base
                page.memsz = region.memsz - (sbrk_base - region.vaddr)
                return page
        return region

    def is_initialized(self):
        addr = pwndbg.gdblib.symbol.address("__libc_malloc_initialized")
        if addr is None:
            addr = pwndbg.gdblib.symbol.address("__malloc_initialized")
        return pwndbg.gdblib.memory.s32(addr) > 0


class SymbolUnresolvableError(Exception):
    def __init__(self, symbol):
        self.symbol = symbol

    def __str__(self):
        return "`%s` can not be resolved via heuristic" % self.symbol


class HeuristicHeap(Heap):
    def __init__(self):
        super().__init__()
        self._thread_arena_offset = None
        self._thread_cache_offset = None
        self._structs_module = None
        self._possible_page_of_symbols = None

    @property
    def struct_module(self):
        if not self._structs_module and pwndbg.glibc.get_version():
            try:
                self._structs_module = importlib.reload(
                    importlib.import_module("pwndbg.heap.structs")
                )
            except Exception:
                pass
        return self._structs_module

    @property
    def possible_page_of_symbols(self):
        if self._possible_page_of_symbols is None:
            if pwndbg.glibc.get_got_plt_address() > 0:
                self._possible_page_of_symbols = pwndbg.gdblib.vmmap.find(
                    pwndbg.glibc.get_got_plt_address()
                )
            elif pwndbg.gdblib.symbol.address("_IO_list_all"):
                self._possible_page_of_symbols = pwndbg.gdblib.vmmap.find(
                    pwndbg.gdblib.symbol.address("_IO_list_all")
                )
        return self._possible_page_of_symbols

    def can_be_resolved(self):
        return self.struct_module is not None

    def is_glibc_symbol(self, addr):
        # If addr is in the same region as `_IO_list_all` and its address is greater than it, we trust it is a symbol of glibc.
        # Note: We should only use this when we can not find the symbol via `pwndbg.gdblib.symbol.static_linkage_symbol_address()`.
        if addr is None:
            return False
        _IO_list_all_addr = pwndbg.gdblib.symbol.address("_IO_list_all")
        if _IO_list_all_addr:
            return addr in pwndbg.gdblib.vmmap.find(_IO_list_all_addr) and addr > _IO_list_all_addr
        # We trust that symbol is from GLIBC :)
        return True

    @property
    def main_arena(self):
        main_arena_via_config = int(str(pwndbg.gdblib.config.main_arena), 0)
        main_arena_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "main_arena"
        ) or pwndbg.gdblib.symbol.address("main_arena")
        if main_arena_via_config > 0:
            self._main_arena_addr = main_arena_via_config
        elif pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "main_arena"
        ) or self.is_glibc_symbol(main_arena_via_symbol):
            self._main_arena_addr = main_arena_via_symbol
        # TODO/FIXME: These are quite dirty, we should find a better way to do this
        if not self._main_arena_addr:
            if (
                pwndbg.glibc.get_version() < (2, 34)
                and pwndbg.gdblib.arch.current != "arm"
                and pwndbg.gdblib.symbol.address("__malloc_hook")
            ):
                malloc_hook_addr = pwndbg.gdblib.symbol.address("__malloc_hook")
                # Credit: This tricks is modified from
                # https://github.com/hugsy/gef/blob/c530aa518ac96dff6fc810a5552ecf54fd1b3581/gef.py#L1189-L1196
                # Thank @_hugsy_ and all the contributors of gef! (But somehow, gef's strategy for arm doesn't seem
                # reliable, at least for my test it isn't work)
                if pwndbg.gdblib.arch.current in ("x86-64", "i386"):
                    self._main_arena_addr = malloc_hook_addr + (
                        (0x20 - (malloc_hook_addr % 0x20)) % 0x20
                    )
                elif pwndbg.gdblib.arch.current == "aarch64":
                    self._main_arena_addr = (
                        malloc_hook_addr - pwndbg.gdblib.arch.ptrsize * 2 - self.malloc_state.sizeof
                    )
            # If we can not find the main_arena via offset trick, we try to find its reference in malloc_trim
            elif pwndbg.gdblib.symbol.address("malloc_trim"):
                # try to find `mstate ar_ptr = &main_arena;` in malloc_trim instructions
                malloc_trim_instructions = pwndbg.disasm.near(
                    pwndbg.gdblib.symbol.address("malloc_trim"), 10, show_prev_insns=False
                )
                if pwndbg.gdblib.arch.current == "x86-64":
                    for instr in malloc_trim_instructions:
                        # try to find `lea rax,[rip+DISP]`
                        if instr.mnemonic == "lea" and "rip" in instr.op_str and instr.disp > 0:
                            self._main_arena_addr = instr.next + instr.disp  # rip + disp
                            break
                elif pwndbg.gdblib.arch.current == "i386" and self.possible_page_of_symbols:
                    base_offset = self.possible_page_of_symbols.vaddr
                    for instr in malloc_trim_instructions:
                        # try to find `lea edi,[eax+DISP]`
                        if instr.mnemonic == "lea" and "eax" in instr.op_str and instr.disp > 0:
                            self._main_arena_addr = base_offset + instr.disp  # eax + disp
                            break
                elif pwndbg.gdblib.arch.current == "aarch64" and self.possible_page_of_symbols:
                    base_offset = self.possible_page_of_symbols.vaddr
                    reg = None
                    for instr in malloc_trim_instructions[5:]:
                        # Try to find `add reg2, reg1, #offset` after `adrp reg1, #base_offset`
                        if instr.mnemonic == "add" and instr.operands[1].str == reg:
                            self._main_arena_addr = base_offset + instr.operands[2].int
                            break
                        if instr.mnemonic == "adrp" and instr.operands[1].int == base_offset:
                            reg = instr.operands[0].str
                elif pwndbg.gdblib.arch.current == "arm":
                    ldrw_instr = None
                    for instr in malloc_trim_instructions:
                        # Try to find `ldr.w reg, [pc, #offset]`, then `add reg, pc`
                        if not ldrw_instr:
                            if instr.mnemonic == "ldr.w":
                                ldrw_instr = instr
                        else:
                            reg = ldrw_instr.operands[0].str
                            if instr.mnemonic == "add" and instr.op_str == reg + ", pc":
                                # ldr.w reg, [pc, #offset]
                                offset = ldrw_instr.operands[1].mem.disp
                                offset = pwndbg.gdblib.memory.s32(
                                    (ldrw_instr.address + 4 & -4) + offset
                                )
                                # add reg, pc
                                self._main_arena_addr = offset + instr.address + 4

            # Try to search main_arena in .data of libc if we can't find it via above trick
            if not self._main_arena_addr or pwndbg.gdblib.vmmap.find(self._main_arena_addr) is None:
                start = pwndbg.gdblib.symbol.address("_IO_2_1_stdin_")
                end = pwndbg.gdblib.symbol.address("_IO_list_all")
                # If we didn't have these symbols, we try to find them in the possible page
                if self.possible_page_of_symbols:
                    start = start or self.possible_page_of_symbols.vaddr
                    end = end or self.possible_page_of_symbols.end
                if start is not None and end is not None:
                    end -= self.malloc_state.sizeof
                    while start < end:
                        start += pwndbg.gdblib.arch.ptrsize
                        if not pwndbg.gdblib.symbol.get(start).startswith("_IO"):
                            break
                    # main_arena is between _IO_2_1_stdin and _IO_list_all
                    for addr in range(start, end, pwndbg.gdblib.arch.ptrsize):
                        found = False
                        tmp_arena = self.malloc_state(addr)
                        tmp_next = int(tmp_arena["next"])
                        # check if the `next` pointer of tmp_arena will point to the same address we guess
                        # e.g. when our process is single-threaded, &tmp_arena->next == &main_arena
                        # when our process is multi-threaded, &tmp_arena->next->...->next == &main_arena
                        while tmp_next > 0:
                            if tmp_next == addr:
                                self._main_arena_addr = addr
                                found = True
                                break
                            tmp_arena = self.malloc_state(tmp_next)
                            if (
                                pwndbg.gdblib.vmmap.find(tmp_arena.get_field_address("next"))
                                is not None
                            ):
                                tmp_next = int(tmp_arena["next"])
                            else:
                                # if `&tmp_arena->next` is not valid, the linked list is broken, break this while loop and try `addr+pwndbg.gdblib.arch.ptrsize` again
                                break
                        if found:
                            break

        if self._main_arena_addr and pwndbg.gdblib.vmmap.find(self._main_arena_addr):
            self._main_arena = self.malloc_state(self._main_arena_addr)
            return self._main_arena

        raise SymbolUnresolvableError("main_arena")

    def has_tcache(self):
        # TODO/FIXME: Can we determine the tcache_bins existence more reliable?

        # There is no debug symbols, we determine the tcache_bins existence by checking glibc version only
        return self.is_initialized() and pwndbg.glibc.get_version() >= (2, 26)

    @property
    def thread_arena(self):
        thread_arena_via_config = int(str(pwndbg.gdblib.config.thread_arena), 0)
        thread_arena_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "thread_arena"
        ) or pwndbg.gdblib.symbol.address("thread_arena")
        if thread_arena_via_config > 0:
            return thread_arena_via_config
        elif thread_arena_via_symbol:
            if pwndbg.gdblib.symbol.static_linkage_symbol_address("thread_arena"):
                # If the symbol is static-linkage symbol, we trust it.
                return pwndbg.gdblib.memory.u(thread_arena_via_symbol)
            # Check &thread_arena is nearby TLS base or not to avoid false positive.
            tls_base = pwndbg.gdblib.tls.address
            if tls_base:
                if pwndbg.gdblib.arch.current in ("x86-64", "i386"):
                    is_valid_address = 0 < tls_base - thread_arena_via_symbol < 0x250
                else:  # elif pwndbg.gdblib.arch.current in ("aarch64", "arm"):
                    is_valid_address = 0 < thread_arena_via_symbol - tls_base < 0x250

                is_valid_address = (
                    is_valid_address
                    and thread_arena_via_symbol in pwndbg.gdblib.vmmap.find(tls_base)
                )

                if is_valid_address:
                    thread_arena_struct_addr = pwndbg.gdblib.memory.u(thread_arena_via_symbol)
                    # Check &thread_arena is a valid address or not to avoid false positive.
                    if pwndbg.gdblib.vmmap.find(thread_arena_struct_addr):
                        return thread_arena_struct_addr

        if not self._thread_arena_offset and pwndbg.gdblib.symbol.address("__libc_calloc"):
            # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
            __libc_calloc_instruction = pwndbg.disasm.near(
                pwndbg.gdblib.symbol.address("__libc_calloc"), 100, show_prev_insns=False
            )
            # try to find the reference to thread_arena in arena_get in __libc_calloc ( ptr = thread_arena; )
            if pwndbg.gdblib.arch.current == "x86-64":
                # try to find something like `mov rax, [rip + disp]`
                # and its next is `mov reg, qword ptr fs:[rax]`
                # and then we can get the tls offset to thread_arena by calculating value of rax

                is_possible = lambda i, instr: (
                    __libc_calloc_instruction[i + 1].op_str.endswith("qword ptr fs:[rax]")
                    and instr.op_str.startswith("rax, qword ptr [rip +")
                )
                get_offset_instruction = next(
                    instr
                    for i, instr in enumerate(__libc_calloc_instruction[:-1])
                    if is_possible(i, instr)
                )
                # rip + disp
                self._thread_arena_offset = pwndbg.gdblib.memory.s64(
                    get_offset_instruction.next + get_offset_instruction.disp
                )
            elif pwndbg.gdblib.arch.current == "i386" and self.possible_page_of_symbols:
                base_offset = self.possible_page_of_symbols.vaddr
                # try to find something like `mov eax, dword ptr [reg + disp]` (disp is a negative value)
                # and its next is either `mov reg, dword ptr gs:[eax]` or `mov reg, dword ptr [reg + eax]`
                # and then we can get the tls offset to thread_arena by calculating value of eax

                # this part is very dirty, but it works
                is_possible = lambda i, instr: (
                    (
                        __libc_calloc_instruction[i + 1].op_str.endswith("gs:[eax]")
                        ^ __libc_calloc_instruction[i + 1].op_str.endswith("+ eax]")
                    )
                    and __libc_calloc_instruction[i + 1].mnemonic == "mov"
                    and instr.mnemonic == "mov"
                    and instr.op_str.startswith("eax, dword ptr [e")
                    and instr.disp < 0
                )
                get_offset_instruction = [
                    instr
                    for i, instr in enumerate(__libc_calloc_instruction[:-1])
                    if is_possible(i, instr)
                ][-1]
                # reg + disp (value of reg is the page start of the last libc page)
                self._thread_arena_offset = pwndbg.gdblib.memory.s32(
                    base_offset + get_offset_instruction.disp
                )
            elif pwndbg.gdblib.arch.current == "aarch64":
                # There's a branch to get main_arena or thread_arena
                # and before the branch, the flow of assembly code will like:
                # `mrs reg1, tpidr_el;
                # adrp reg2, #base_offset;
                # ldr reg2, [reg2, #offset]
                # /* branch(cbnz) to arena_get or use main_arena */;
                # /* if branch to thread_arena*/;
                # ldr reg3, [reg1, reg2]`
                # Or:
                # `adrp	reg1, #base_offset;
                # ldr reg1, [reg1, #offset];
                # mrs reg2, tpidr_el;
                # /* branch(cbnz) to arena_get or use main_arena */;
                # /* if branch to thread_arena*/;
                # ldr reg2, [reg1, reg2]`
                # , then reg3 or reg2 will be &thread_arena
                mrs_instr = next(
                    instr for instr in __libc_calloc_instruction if instr.mnemonic == "mrs"
                )
                min_adrp_distance = 0x1000  # just a big enough number
                nearest_adrp = None
                nearest_adrp_idx = 0
                for i, instr in enumerate(__libc_calloc_instruction):
                    if (
                        instr.mnemonic == "adrp"
                        and abs(mrs_instr.address - instr.address) < min_adrp_distance
                    ):
                        reg = instr.operands[0].str
                        nearest_adrp = instr
                        nearest_adrp_idx = i
                        min_adrp_distance = abs(mrs_instr.address - instr.address)
                    if instr.address - mrs_instr.address > min_adrp_distance:
                        break
                for instr in __libc_calloc_instruction[nearest_adrp_idx + 1 :]:
                    if instr.mnemonic == "ldr":
                        base_offset = nearest_adrp.operands[1].int
                        offset = instr.operands[1].mem.disp
                        self._thread_arena_offset = pwndbg.gdblib.memory.s64(base_offset + offset)
                        break

            elif pwndbg.gdblib.arch.current == "arm":
                # We need to find something near the first `mrc 15, ......`
                # The flow of assembly code will like:
                # `ldr reg1, [pc, #offset];
                # mrc 15, 0, reg2, cr13, cr0, {3};
                # add reg1, pc;
                # ldr reg1, [reg1];
                # add reg1, reg2`
                # , then reg1 will be &thread_arena
                found_mrc = False
                ldr_instr = None
                for instr in __libc_calloc_instruction:
                    if not found_mrc:
                        if instr.mnemonic == "mrc":
                            found_mrc = True
                        elif instr.mnemonic == "ldr":
                            ldr_instr = instr
                    else:
                        reg = ldr_instr.operands[0].str
                        if instr.mnemonic == "add" and instr.op_str == reg + ", pc":
                            offset = ldr_instr.operands[1].mem.disp
                            offset = pwndbg.gdblib.memory.s32((ldr_instr.address + 4 & -4) + offset)
                            self._thread_arena_offset = pwndbg.gdblib.memory.s32(
                                instr.address + 4 + offset
                            )
                            break

        if self._thread_arena_offset:
            tls_base = pwndbg.gdblib.tls.address
            if tls_base:
                thread_arena_struct_addr = tls_base + self._thread_arena_offset
                if pwndbg.gdblib.vmmap.find(thread_arena_struct_addr):
                    return pwndbg.gdblib.memory.pvoid(thread_arena_struct_addr)

        raise SymbolUnresolvableError("thread_arena")

    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. We try to find its address in Thread Local Storage (TLS) first,
        and if that fails, we guess it's at the first chunk of the heap.
        """
        thread_cache_via_config = int(str(pwndbg.gdblib.config.tcache), 0)
        thread_cache_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "tcache"
        ) or pwndbg.gdblib.symbol.address("tcache")
        if thread_cache_via_config > 0:
            self._thread_cache = self.tcache_perthread_struct(thread_cache_via_config)
            return self._thread_cache
        elif thread_cache_via_symbol:
            if pwndbg.gdblib.symbol.static_linkage_symbol_address("tcache"):
                # If the symbol is static-linkage symbol, we trust it.
                thread_cache_struct_addr = pwndbg.gdblib.memory.u(thread_cache_via_symbol)
                self._thread_cache = self.tcache_perthread_struct(thread_cache_struct_addr)
                return self._thread_cache
            # Check &tcache is nearby TLS base or not to avoid false positive.
            tls_base = pwndbg.gdblib.tls.address
            if tls_base:
                if pwndbg.gdblib.arch.current in ("x86-64", "i386"):
                    is_valid_address = 0 < tls_base - thread_cache_via_symbol < 0x250
                else:  # elif pwndbg.gdblib.arch.current in ("aarch64", "arm"):
                    is_valid_address = 0 < thread_cache_via_symbol - tls_base < 0x250

                is_valid_address = (
                    is_valid_address
                    and thread_cache_via_symbol in pwndbg.gdblib.vmmap.find(tls_base)
                )

                if is_valid_address:
                    thread_cache_struct_addr = pwndbg.gdblib.memory.u(thread_cache_via_symbol)
                    # Check *tcache is in the heap region or not to avoid false positive.
                    if thread_cache_struct_addr in self.get_heap_boundaries():
                        self._thread_cache = self.tcache_perthread_struct(thread_cache_struct_addr)
                        return self._thread_cache

        if self.has_tcache():
            # Each thread has a tcache struct, and the address of the tcache struct is stored in the TLS.

            # Try to find tcache in TLS, so first we need to find the offset of tcache to TLS base
            if not self._thread_cache_offset and pwndbg.gdblib.symbol.address("__libc_malloc"):
                # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
                __libc_malloc_instruction = pwndbg.disasm.near(
                    pwndbg.gdblib.symbol.address("__libc_malloc"), 100, show_prev_insns=False
                )[10:]
                # Try to find the reference to tcache in __libc_malloc, the target C code is like this:
                # `if (tc_idx < mp_.tcache_bins && tcache && ......`
                if pwndbg.gdblib.arch.current == "x86-64":
                    # Find the last `mov reg1, qword ptr [rip + disp]` before the first `mov reg2, fs:[reg1]`
                    # In other words, find the first __thread variable

                    get_offset_instruction = None

                    for instr in __libc_malloc_instruction:
                        if ", qword ptr [rip +" in instr.op_str:
                            get_offset_instruction = instr
                        if ", qword ptr fs:[r" in instr.op_str:
                            break

                    if get_offset_instruction:
                        # rip + disp
                        self._thread_cache_offset = pwndbg.gdblib.memory.s64(
                            get_offset_instruction.next + get_offset_instruction.disp
                        )
                elif pwndbg.gdblib.arch.current == "i386" and self.possible_page_of_symbols:
                    # We still need to find the first __thread variable like we did for x86-64 But the assembly code
                    # of i386 is a little bit unstable sometimes(idk why), there are two versions of the code:
                    # 1. Find the last `mov reg1, dword ptr [reg0 + disp]` before the first `mov reg2, gs:[reg1]`(disp
                    # is a negative value)
                    # 2. Find the first `mov reg1, dword ptr [reg0 + disp]` after `mov reg3,
                    # [reg1 + reg2]` (disp is a negative value), and reg2 is from `mov reg2, gs:[0]`

                    get_offset_instruction = None
                    find_after = False

                    for instr in __libc_malloc_instruction:
                        if (
                            instr.disp < 0
                            and instr.mnemonic == "mov"
                            and ", dword ptr [e" in instr.op_str
                        ):
                            get_offset_instruction = instr
                            if find_after:
                                break
                        if ", dword ptr gs:[e" in instr.op_str:
                            break
                        elif instr.op_str.endswith("gs:[0]") and instr.mnemonic == "mov":
                            find_after = True

                    if get_offset_instruction:
                        # reg + disp (value of reg is the page start of the last libc page)
                        base_offset = self.possible_page_of_symbols.vaddr
                        self._thread_cache_offset = pwndbg.gdblib.memory.s32(
                            base_offset + get_offset_instruction.disp
                        )
                elif pwndbg.gdblib.arch.current == "aarch64":
                    # The logic is the same as the previous one..
                    # The assembly code to access tcache is sth like:
                    # `mrs reg1, tpidr_el0;
                    # adrp reg2, #base_offset;
                    # ldr reg2, [reg2, #offset]
                    # ...
                    # add reg3, reg1, reg2;
                    # ldr reg3, [reg3, #8]`
                    # Or:
                    # `adrp reg2, #base_offset;
                    # mrs reg1, tpidr_el0;
                    # ldr reg2, [reg2, #offset]
                    # ...
                    # add reg3, reg1, reg2;
                    # ldr reg3, [reg3, #8]`
                    # , then reg3 will be &tcache
                    mrs_instr = next(
                        instr for instr in __libc_malloc_instruction if instr.mnemonic == "mrs"
                    )
                    min_adrp_distance = 0x1000  # just a big enough number
                    nearest_adrp = None
                    nearest_adrp_idx = 0
                    for i, instr in enumerate(__libc_malloc_instruction):
                        if (
                            instr.mnemonic == "adrp"
                            and abs(mrs_instr.address - instr.address) < min_adrp_distance
                        ):
                            reg = instr.operands[0].str
                            nearest_adrp = instr
                            nearest_adrp_idx = i
                            min_adrp_distance = abs(mrs_instr.address - instr.address)
                        if instr.address - mrs_instr.address > min_adrp_distance:
                            break
                    for instr in __libc_malloc_instruction[nearest_adrp_idx + 1 :]:
                        if instr.mnemonic == "ldr":
                            base_offset = nearest_adrp.operands[1].int
                            offset = instr.operands[1].mem.disp
                            self._thread_cache_offset = (
                                pwndbg.gdblib.memory.s64(base_offset + offset) + 8
                            )
                            break
                elif pwndbg.gdblib.arch.current == "arm":
                    # We need to find something near the first `mrc 15, ......`
                    # The flow of assembly code will like:
                    # `ldr reg1, [pc, #offset];
                    # ...
                    # mrc 15, 0, reg2, cr13, cr0, {3};
                    # ...
                    # add reg1, pc;
                    # ldr reg1, [reg1];
                    # ...
                    # add reg1, reg2
                    # ...
                    # ldr reg3, [reg1, #4]`
                    # , then reg3 will be tcache address
                    found_mrc = False
                    ldr_instr = None
                    for instr in __libc_malloc_instruction:
                        if not found_mrc:
                            if instr.mnemonic == "mrc":
                                found_mrc = True
                            elif instr.mnemonic == "ldr":
                                ldr_instr = instr
                        else:
                            reg = ldr_instr.operands[0].str
                            if instr.mnemonic == "add" and instr.op_str == reg + ", pc":
                                offset = ldr_instr.operands[1].mem.disp
                                offset = pwndbg.gdblib.memory.s32(
                                    (ldr_instr.address + 4 & -4) + offset
                                )
                                self._thread_cache_offset = (
                                    pwndbg.gdblib.memory.s32(instr.address + 4 + offset) + 4
                                )
                                break

            # Validate the the offset we found
            is_offset_valid = False

            if pwndbg.gdblib.arch.current in ("x86-64", "i386"):
                # The offset to tls should be a negative integer for x86/x64, but it can't be too small
                # If it is too small, we find a wrong value
                is_offset_valid = (
                    self._thread_cache_offset and -0x250 < self._thread_cache_offset < 0
                )
            elif pwndbg.gdblib.arch.current in ("aarch64", "arm"):
                # The offset to tls should be a positive integer for aarch64, but it can't be too big
                # If it is too big, we find a wrong value
                is_offset_valid = (
                    self._thread_cache_offset and 0 < self._thread_cache_offset < 0x250
                )

            is_offset_valid = (
                is_offset_valid and self._thread_cache_offset % pwndbg.gdblib.arch.ptrsize == 0
            )

            # If the offset is valid, we add the offset to TLS base to locate the tcache struct
            # Note: We do a lot of checks here to make sure the offset and address we found is valid,
            # so we can use our fallback if they're invalid
            if is_offset_valid:
                tls_base = pwndbg.gdblib.tls.address
                if tls_base:
                    thread_cache_struct_addr = pwndbg.gdblib.memory.pvoid(
                        tls_base + self._thread_cache_offset
                    )
                    if (
                        pwndbg.gdblib.vmmap.find(thread_cache_struct_addr)
                        and thread_cache_struct_addr in self.get_heap_boundaries()
                    ):
                        self._thread_cache = self.tcache_perthread_struct(thread_cache_struct_addr)
                        return self._thread_cache

            # If we still can't find the tcache, we guess tcache is in the first chunk of the heap
            # Note: The result might be wrong if the arena is being shared by multiple threads
            # And that's why we need to find the tcache address in TLS first
            arena = self.get_arena()
            heap_region = self.get_heap_boundaries()
            ptr_size = pwndbg.gdblib.arch.ptrsize
            if arena == self.main_arena:
                cursor = heap_region.start
            else:
                cursor = heap_region.start + self.heap_info.sizeof
                if (
                    pwndbg.gdblib.vmmap.find(self.get_heap(heap_region.start)["ar_ptr"])
                    == heap_region
                ):
                    # Round up to a 2-machine-word alignment after an arena to
                    # compensate for the presence of the have_fastchunks variable
                    # in GLIBC versions >= 2.27.
                    cursor += (self.malloc_state.sizeof + ptr_size) & ~self.malloc_align_mask

            # i686 alignment heuristic
            first_chunk_size = pwndbg.gdblib.arch.unpack(
                pwndbg.gdblib.memory.read(cursor + ptr_size, ptr_size)
            )
            if first_chunk_size == 0:
                cursor += ptr_size * 2

            self._thread_cache = self.tcache_perthread_struct(cursor + ptr_size * 2)

            return self._thread_cache

        print(message.warn("This version of GLIBC was not compiled with tcache support."))
        return None

    @property
    def mp(self):
        mp_via_config = int(str(pwndbg.gdblib.config.mp), 0)
        mp_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "mp_"
        ) or pwndbg.gdblib.symbol.address("mp_")
        if mp_via_config > 0:
            self._mp_addr = mp_via_config
        elif pwndbg.gdblib.symbol.static_linkage_symbol_address("mp_") or self.is_glibc_symbol(
            mp_via_symbol
        ):
            self._mp_addr = mp_via_symbol
        if not self._mp_addr and pwndbg.gdblib.symbol.address("__libc_free"):
            # try to find mp_ referenced in __libc_free
            # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
            __libc_free_instructions = pwndbg.disasm.near(
                pwndbg.gdblib.symbol.address("__libc_free"), 100, show_prev_insns=False
            )
            if pwndbg.gdblib.arch.current == "x86-64":
                iter_possible_match = (
                    instr
                    for instr in __libc_free_instructions
                    if instr.mnemonic == "mov"
                    and instr.disp > 0
                    and instr.op_str.startswith("qword ptr [rip +")
                )
                try:
                    # mov qword ptr [rip + (mp.mmap_threshold offset)], reg
                    mp_mmap_threshold_ref = next(iter_possible_match)
                    # mov qword ptr [rip + (mp offset)], reg
                    mp_ref = next(iter_possible_match)
                    # references to mp_.mmap_threshold and mp_ are very close to each other
                    while mp_mmap_threshold_ref.next - mp_ref.address > 0x10:
                        mp_mmap_threshold_ref = mp_ref
                        mp_ref = next(iter_possible_match)
                    self._mp_addr = mp_ref.next + mp_ref.disp
                except StopIteration:
                    pass
            elif pwndbg.gdblib.arch.current == "i386" and self.possible_page_of_symbols:
                iter_possible_match = (
                    instr
                    for instr in __libc_free_instructions
                    if instr.mnemonic == "mov"
                    and instr.disp > 0
                    and instr.op_str.startswith("dword ptr [")
                )
                base_offset = self.possible_page_of_symbols.vaddr
                try:
                    # mov dword ptr [base_offset + (mp.mmap_threshold offset)], reg
                    mp_mmap_threshold_ref = next(iter_possible_match)
                    # mov dword ptr [base_offset + (mp offset)], reg
                    mp_ref = next(iter_possible_match)
                    # references to mp_.mmap_threshold and mp_ are very close to each other
                    while mp_mmap_threshold_ref.next - mp_ref.address > 0x10:
                        mp_mmap_threshold_ref = mp_ref
                        mp_ref = next(iter_possible_match)
                    self._mp_addr = base_offset + mp_ref.disp
                except StopIteration:
                    pass
            elif pwndbg.gdblib.arch.current == "aarch64" and self.possible_page_of_symbols:
                base_offset = self.possible_page_of_symbols.vaddr
                regs = set()
                found = False
                for instr in __libc_free_instructions:
                    if found:
                        break
                    # We want to find sth like: `str reg2, [reg1, #offset]``
                    # and reg1 is from `adrp reg1, base_offset`
                    # We can notice that it only have one match in __libc_free
                    # The match should be the reference to mp_
                    if instr.mnemonic == "str":
                        for reg in regs:
                            if "[" + reg in instr.op_str:
                                self._mp_addr = base_offset + instr.operands[1].mem.disp
                                found = True
                                break
                    elif instr.mnemonic == "adrp" and instr.operands[1].int == base_offset:
                        regs.add(instr.operands[0].str)
            elif pwndbg.gdblib.arch.current == "arm":
                regs = {}
                ldr = {}
                found = False
                for instr in __libc_free_instructions:
                    if found:
                        break
                    # We want to find sth like: `str reg2, [reg1, #8 or #0]`
                    # and reg1 is from `ldr reg1, [pc, #offset]` and `add reg1, pc`
                    # We can notice that it only have one match in __libc_free
                    # The match should be the reference to mp_ and mp_.mmap_threshold
                    if instr.mnemonic == "str":
                        for reg in regs:
                            if "[" + reg + "]" in instr.op_str:
                                # ldr reg1, [pc, #offset]
                                offset = regs[reg].operands[1].mem.disp
                                offset = pwndbg.gdblib.memory.s32(
                                    (regs[reg].address + 4 & -4) + offset
                                )
                                # add reg1, pc
                                self._mp_addr = offset + ldr[reg].address + 4
                                found = True
                                break
                    elif instr.mnemonic == "add":
                        for reg in regs:
                            if instr.op_str == reg + ", pc":
                                ldr[reg] = instr
                    elif instr.mnemonic == "ldr" and "[pc," in instr.op_str:
                        regs[instr.operands[0].str] = instr

        # can't find the reference about mp_ in __libc_free, try to find it with heap boundaries of main_arena
        if (
            not self._mp_addr
            or pwndbg.gdblib.vmmap.find(self._mp_addr) is None
            and self.possible_page_of_symbols
        ):
            libc_page = self.possible_page_of_symbols

            # try to find sbrk_base via main_arena or vmmap
            # TODO/FIXME: If mp_.sbrk_base is not same as heap region start, this will fail
            try:
                arena = self.main_arena
            except SymbolUnresolvableError:
                arena = None
            region = None
            # Try to find heap region via `main_arena.top`
            if self._main_arena_addr and arena:
                region = self.get_region(arena["top"])
            # If we can't use `main_arena` to find the heap region, try to find it via vmmap
            region = region or next(
                (p for p in pwndbg.gdblib.vmmap.get() if "[heap]" == p.objfile), None
            )
            if region is not None:
                possible_sbrk_base = region.start

                sbrk_offset = self.malloc_par(0).get_field_address("sbrk_base")
                # try to search sbrk_base in a part of libc page
                result = pwndbg.search.search(
                    pwndbg.gdblib.arch.pack(possible_sbrk_base),
                    start=libc_page.start,
                    end=libc_page.end,
                )
                try:
                    self._mp_addr = next(result) - sbrk_offset
                except StopIteration:
                    pass

        if self._mp_addr and pwndbg.gdblib.vmmap.find(self._mp_addr) is not None:
            self._mp = self.malloc_par(self._mp_addr)
            return self._mp

        raise SymbolUnresolvableError("mp_")

    @property
    def global_max_fast(self):
        global_max_fast_via_config = int(str(pwndbg.gdblib.config.global_max_fast), 0)
        global_max_fast_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "global_max_fast"
        ) or pwndbg.gdblib.symbol.address("global_max_fast")
        if global_max_fast_via_config > 0:
            self._global_max_fast_addr = global_max_fast_via_config
        elif pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "global_max_fast"
        ) or self.is_glibc_symbol(global_max_fast_via_symbol):
            self._global_max_fast_addr = global_max_fast_via_symbol
        # TODO/FIXME: This method should be updated if we find a better way to find the target assembly code
        if not self._global_max_fast_addr and pwndbg.gdblib.symbol.address("__libc_malloc"):
            # `__libc_malloc` will call `_int_malloc`, so we try to find the reference to `_int_malloc`
            # because there is a reference to global_max_fast in _int_malloc, which is:
            # `if ((unsigned long) (nb) <= (unsigned long) (get_max_fast ()))`
            __libc_malloc_instructions = pwndbg.disasm.near(
                pwndbg.gdblib.symbol.address("__libc_malloc"), 25, show_prev_insns=False
            )
            if pwndbg.gdblib.arch.current == "x86-64":
                _int_malloc_addr = (
                    next(
                        instr
                        for instr in __libc_malloc_instructions[5:]
                        if instr.mnemonic == "call"
                    )
                    .operands[0]
                    .imm
                )
                _int_malloc_instructions = pwndbg.disasm.near(
                    _int_malloc_addr, 25, show_prev_insns=False
                )
                # find first `cmp` instruction like: `cmp something, qword ptr [rip + disp]`
                global_max_fast_ref = next(
                    instr
                    for instr in _int_malloc_instructions
                    if instr.mnemonic == "cmp" and "qword ptr [rip +" in instr.op_str
                )
                self._global_max_fast_addr = global_max_fast_ref.next + global_max_fast_ref.disp
            elif pwndbg.gdblib.arch.current == "i386" and self.possible_page_of_symbols:
                _int_malloc_addr = (
                    next(
                        instr
                        for instr in __libc_malloc_instructions[5:]
                        if instr.mnemonic == "call"
                    )
                    .operands[0]
                    .imm
                )
                _int_malloc_instructions = pwndbg.disasm.near(
                    _int_malloc_addr, 25, show_prev_insns=False
                )
                base_offset = self.possible_page_of_symbols.vaddr
                # cmp reg, [base_offset + global_max_fast_offset]
                global_max_fast_ref = next(
                    instr
                    for instr in _int_malloc_instructions
                    if instr.mnemonic == "cmp" and "dword ptr [" in instr.op_str
                )
                self._global_max_fast_addr = base_offset + global_max_fast_ref.disp
            elif pwndbg.gdblib.arch.current == "aarch64" and self.possible_page_of_symbols:
                _int_malloc_addr = (
                    next(
                        instr for instr in __libc_malloc_instructions[5:] if instr.mnemonic == "bl"
                    )
                    .operands[0]
                    .imm
                )
                _int_malloc_instructions = pwndbg.disasm.near(
                    _int_malloc_addr, 25, show_prev_insns=False
                )
                base_offset = self.possible_page_of_symbols.vaddr
                reg = None
                for instr in _int_malloc_instructions:
                    # We want to find sth like:
                    # `adrp reg1, #base_offset;
                    # add reg2, reg1, #offset;
                    # ldr reg2, [reg2, #8];
                    # cmp reg2, #0x1f;`
                    # Or:
                    # `adrp reg, #base_offset;
                    # ...
                    # ldr reg2, [reg, #offset];
                    # cmp reg3, reg2; (reg3 stored 0x1f)`
                    # So global_max_fast address is `base_offset+offset+8` or `base_offset+offset`
                    if reg:
                        if instr.mnemonic == "add" and reg + ", #" in instr.op_str:
                            self._global_max_fast_addr = base_offset + instr.operands[2].int + 8
                            break
                        elif instr.mnemonic == "ldr" and reg + ", #" in instr.op_str:
                            self._global_max_fast_addr = base_offset + instr.operands[1].mem.disp
                            break
                    elif instr.mnemonic == "adrp" and instr.operands[1].int == base_offset:
                        reg = instr.operands[0].str
            elif pwndbg.gdblib.arch.current == "arm":
                _int_malloc_addr = (
                    next(
                        instr for instr in __libc_malloc_instructions[5:] if instr.mnemonic == "bl"
                    )
                    .operands[0]
                    .imm
                )
                _int_malloc_instructions = pwndbg.disasm.near(
                    _int_malloc_addr, 25, show_prev_insns=False
                )
                ldr_instr = None
                for instr in _int_malloc_instructions:
                    # We want to find sth like:
                    # `ldr r3, [pc, #612];
                    # add r3, pc;
                    # ldr r3, [r3, #4];
                    # cmp r3, #15`
                    if (
                        ldr_instr
                        and instr.mnemonic == "add"
                        and instr.op_str == ldr_instr.operands[0].str + ", pc"
                    ):
                        # ldr r3, [pc, #612]
                        offset = ldr_instr.operands[1].mem.disp
                        offset = pwndbg.gdblib.memory.s32((ldr_instr.address + 4 & -4) + offset)
                        # add r3, pc; ldr r3, [r3, #4];
                        self._global_max_fast_addr = offset + instr.address + 8
                        break
                    elif instr.mnemonic == "ldr" and "[pc" in instr.op_str:
                        ldr_instr = instr

        if self._global_max_fast_addr and pwndbg.gdblib.vmmap.find(self._global_max_fast_addr):
            self._global_max_fast = pwndbg.gdblib.memory.u(self._global_max_fast_addr)
            return self._global_max_fast

        raise SymbolUnresolvableError("global_max_fast")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def heap_info(self):
        return self.struct_module.HeapInfo

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_chunk(self):
        return self.struct_module.MallocChunk

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_state(self):
        return self.struct_module.MallocState

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_perthread_struct(self):
        return self.struct_module.TcachePerthreadStruct

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def tcache_entry(self):
        return self.struct_module.TcacheEntry

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def mallinfo(self):
        # TODO/FIXME: Currently, we don't need to create a new class for `struct mallinfo` because we never use it.
        raise NotImplementedError("`struct mallinfo` is not implemented yet.")

    @property
    @pwndbg.lib.memoize.reset_on_objfile
    def malloc_par(self):
        return self.struct_module.MallocPar

    def get_heap(self, addr):
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        return self.heap_info(heap_for_ptr(addr))

    def get_arena(self, arena_addr=None):
        """Read a malloc_state struct from the specified address, default to
        reading the current thread's arena. Return the main arena if the
        current thread is not attached to an arena.
        """
        if arena_addr is None:
            if self.multithreaded:
                thread_arena = self.thread_arena
                if thread_arena > 0:
                    return self.malloc_state(thread_arena)

            return self.main_arena

        return self.malloc_state(arena_addr)

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return self.tcache_perthread_struct(tcache_addr)

    def get_heap_boundaries(self, addr=None):
        """Find the boundaries of the heap containing `addr`, default to the
        boundaries of the heap containing the top chunk for the thread's arena.
        """
        try:
            region = self.get_region(addr) if addr else self.get_region(self.get_arena()["top"])
        except Exception:
            # Although `self.get_arena` should only raise `SymbolUnresolvableError`, we catch all exceptions here to avoid some bugs in main_arena's heuristics break this function :)
            pass
        # If we can't use arena to find the heap region, we use vmmap to find the heap region
        region = next((p for p in pwndbg.gdblib.vmmap.get() if "[heap]" == p.objfile), None)
        if region is not None and addr is not None:
            region = None if addr not in region else region

        # Occasionally, the [heap] vm region and the actual start of the heap are
        # different, e.g. [heap] starts at 0x61f000 but mp_.sbrk_base is 0x620000.
        # Return an adjusted Page object if this is the case.
        if not self._mp_addr:
            try:
                self.mp  # try to fetch the mp_ structure to make sure it's initialized
            except Exception:
                # Although `self.mp` should only raise `SymbolUnresolvableError`, we catch all exceptions here to avoid some bugs in mp_'s heuristics break this function :)
                pass
        if self._mp_addr:  # sometimes we can't find mp_ via heuristics
            page = pwndbg.lib.memory.Page(0, 0, 0, 0)
            # make sure mp["sbrk_base"] is valid
            if self.get_region(self.mp.get_field_address("sbrk_base")) and self.get_region(
                self.mp["sbrk_base"]
            ):
                sbrk_base = int(self.mp["sbrk_base"])
                if region == self.get_region(sbrk_base):
                    if sbrk_base != region.vaddr:
                        page.vaddr = sbrk_base
                        page.memsz = region.memsz - (sbrk_base - region.vaddr)
                        return page
        return region

    def is_initialized(self):
        # TODO/FIXME: If main_arena['top'] is been modified to 0, this will not work.
        # try to use vmmap or main_arena.top to find the heap
        return (
            any("[heap]" == x.objfile for x in pwndbg.gdblib.vmmap.get())
            or self.main_arena["top"] != 0
        )
