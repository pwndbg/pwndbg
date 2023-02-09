import copy
import importlib
from collections import OrderedDict
from enum import Enum
from typing import Union  # noqa: F401

import gdb

import pwndbg.disasm
import pwndbg.gdblib.config
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.tls
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap
import pwndbg.glibc
import pwndbg.search
from pwndbg.color import message
from pwndbg.color.memory import c as M
from pwndbg.constants import ptmalloc
from pwndbg.heap import heap_chain_limit

# See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l30
# and https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l869
# 1 Mb (x86) or 64 Mb (x64)
HEAP_MAX_SIZE = 1024 * 1024 if pwndbg.gdblib.arch.ptrsize == 4 else 2 * 4 * 1024 * 1024 * 8

NBINS = 128
BINMAPSIZE = 4
TCACHE_MAX_BINS = 64
NFASTBINS = 10
NSMALLBINS = 64


# Note that we must inherit from `str` before `Enum`: https://stackoverflow.com/a/58608362/803801
class BinType(str, Enum):
    TCACHE = "tcachebins"
    FAST = "fastbins"
    SMALL = "smallbins"
    LARGE = "largebins"
    UNSORTED = "unsortedbin"
    NOT_IN_BIN = "not_in_bin"

    def valid_fields(self):
        if self in [BinType.FAST, BinType.TCACHE]:
            return ["fd"]
        elif self in [BinType.SMALL, BinType.UNSORTED]:
            return ["fd", "bk"]
        elif self == BinType.LARGE:
            return ["fd", "bk", "fd_nextsize", "bk_nextsize"]


class Bin:
    def __init__(self, fd_chain, bk_chain=None, count=None, is_corrupted=False) -> None:
        self.fd_chain = fd_chain
        self.bk_chain = bk_chain
        self.count = count
        self.is_corrupted = is_corrupted

    def contains_chunk(self, chunk) -> bool:
        return chunk in self.fd_chain

    @staticmethod
    def size_to_display_name(size):
        if size == "all":
            return size

        assert isinstance(size, int)

        return hex(size)


class Bins:
    def __init__(self, bin_type) -> None:
        # `typing.OrderedDict` requires Python 3.7
        self.bins = OrderedDict()  # type: OrderedDict[Union[int, str], Bin]
        self.bin_type = bin_type

    # TODO: There's a bunch of bin-specific logic in here, maybe we should
    # subclass and put that logic in there
    def contains_chunk(self, size, chunk):
        # TODO: It will be the same thing, but it would be better if we used
        # pwndbg.heap.current.size_sz. I think each bin should already have a
        # reference to the allocator and shouldn't need to access the `current`
        # variable
        ptr_size = pwndbg.gdblib.arch.ptrsize

        if self.bin_type == BinType.UNSORTED:
            # The unsorted bin only has one bin called 'all'

            # TODO: We shouldn't be mixing int and str types like this
            size = "all"
        elif self.bin_type == BinType.LARGE:
            # All the other bins (other than unsorted) store chunks of the same
            # size in a bin, so we can use the size directly. But the largebin
            # stores a range of sizes, so we need to compute which bucket this
            # chunk falls into

            # TODO: Refactor this, the bin should know how to calculate
            # largebin_index without calling into the allocator
            size = pwndbg.heap.current.largebin_index(size) - NSMALLBINS

        elif self.bin_type == BinType.TCACHE:
            # Unlike fastbins, tcache bins don't store the chunk address in the
            # bins, they store the address of the fd pointer, so we need to
            # search for that address in the tcache bin instead

            # TODO: Can we use chunk_key_offset?
            chunk += ptr_size * 2

        if size in self.bins:
            return self.bins[size].contains_chunk(chunk)

        return False


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
        "_heap",
        "_arena",
        "_is_top_chunk",
    )

    def __init__(self, addr, heap=None, arena=None) -> None:
        if isinstance(pwndbg.heap.current.malloc_chunk, gdb.Type):
            self._gdbValue = pwndbg.gdblib.memory.poi(pwndbg.heap.current.malloc_chunk, addr)
        else:
            self._gdbValue = pwndbg.heap.current.malloc_chunk(addr)
        self.address = int(self._gdbValue.address)
        self._prev_size: int = None
        self._size: int = None
        self._real_size: int = None
        self._flags: int = None
        self._non_main_arena: bool = None
        self._is_mmapped: bool = None
        self._prev_inuse: bool = None
        self._fd = None
        self._bk = None
        self._fd_nextsize = None
        self._bk_nextsize = None
        self._heap = heap
        self._arena = arena
        self._is_top_chunk: bool = None

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
                    self._gdbValue[self.__match_renamed_field("size")] & ~(ptmalloc.SIZE_BITS)
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
    def heap(self):
        if self._heap is None:
            self._heap = Heap(self.address)

        return self._heap

    @property
    def arena(self):
        if self._arena is None:
            self._arena = self.heap.arena

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

    def next_chunk(self):
        if self.is_top_chunk:
            return None

        if self.real_size == 0:
            return None

        next = Chunk(self.address + self.real_size, arena=self.arena)
        if pwndbg.gdblib.memory.is_readable_address(next.address):
            return next
        else:
            return None


class Heap:
    __slots__ = (
        "_gdbValue",
        "arena",
        "_memory_region",
        "start",
        "end",
        "_prev",
        "first_chunk",
    )

    def __init__(self, addr, arena=None) -> None:
        """Build a Heap object given an address on that heap.
        Heap regions are treated differently depending on their arena:
        1) main_arena - uses the sbrk heap
        2) non-main arena - heap starts after its heap_info struct (and possibly an arena)
        3) non-contiguous main_arena - just a memory region
        4) no arena - for fake/mmapped chunks
        """
        allocator = pwndbg.heap.current
        main_arena = allocator.main_arena

        sbrk_region = allocator.get_sbrk_heap_region()
        if addr in sbrk_region:
            # Case 1; main_arena.
            self.arena = main_arena if arena is None else arena
            self._memory_region = sbrk_region
            self._gdbValue = None
        else:
            heap_region = allocator.get_region(addr)
            heap_info = allocator.get_heap(addr)
            try:
                ar_ptr = int(heap_info["ar_ptr"])
            except gdb.MemoryError:
                ar_ptr = None

            if ar_ptr is not None and ar_ptr in (ar.address for ar in allocator.arenas):
                # Case 2; non-main arena.
                self.arena = Arena(ar_ptr) if arena is None else arena
                start = heap_region.start + allocator.heap_info.sizeof
                if ar_ptr in heap_region:
                    start += pwndbg.lib.memory.align_up(
                        allocator.malloc_state.sizeof, allocator.malloc_alignment
                    )

                heap_region.memsz = heap_region.end - start
                heap_region.vaddr = start
                self._memory_region = heap_region
                self._gdbValue = heap_info
            elif main_arena.non_contiguous:
                # Case 3; non-contiguous main_arena.
                self.arena = main_arena if arena is None else arena
                self._memory_region = heap_region
                self._gdbValue = None
            else:
                # Case 4; fake/mmapped chunk
                self.arena = None
                self._memory_region = heap_region
                self._gdbValue = None

        self.start = self._memory_region.start
        self.end = self._memory_region.end
        self.first_chunk = Chunk(self.start)

        self._prev = None

    @property
    def prev(self):
        if self._prev is None and self._gdbValue is not None:
            try:
                self._prev = int(self._gdbValue["prev"])
            except gdb.MemoryError:
                pass

        return self._prev

    def __iter__(self):
        iter_chunk = self.first_chunk
        while iter_chunk is not None:
            yield iter_chunk
            iter_chunk = iter_chunk.next_chunk()

    def __contains__(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __str__(self) -> str:
        fmt = "[%%%ds]" % (pwndbg.gdblib.arch.ptrsize * 2)
        return message.hint(fmt % (hex(self.first_chunk.address))) + M.heap(
            str(pwndbg.gdblib.vmmap.find(self.start))
        )


class Arena:
    __slots__ = (
        "_gdbValue",
        "address",
        "_is_main_arena",
        "_top",
        "_active_heap",
        "_heaps",
        "_mutex",
        "_flags",
        "_non_contiguous",
        "_have_fastchunks",
        "_fastbinsY",
        "_bins",
        "_binmap",
        "_next",
        "_next_free",
        "_system_mem",
    )

    def __init__(self, addr) -> None:
        if isinstance(pwndbg.heap.current.malloc_state, gdb.Type):
            self._gdbValue = pwndbg.gdblib.memory.poi(pwndbg.heap.current.malloc_state, addr)
        else:
            self._gdbValue = pwndbg.heap.current.malloc_state(addr)

        self.address = int(self._gdbValue.address)
        self._is_main_arena: bool = None
        self._top = None
        self._active_heap = None
        self._heaps = None
        self._mutex = None
        self._flags = None
        self._non_contiguous = None
        self._have_fastchunks = None
        self._fastbinsY = None
        self._bins = None
        self._binmap = None
        self._next = None
        self._next_free = None
        self._system_mem = None

    @property
    def is_main_arena(self):
        if self._is_main_arena is None:
            self._is_main_arena = self.address == pwndbg.heap.current.main_arena.address

        return self._is_main_arena

    @property
    def mutex(self):
        if self._mutex is None:
            try:
                self._mutex = int(self._gdbValue["mutex"])
            except gdb.MemoryError:
                pass

        return self._mutex

    @property
    def flags(self):
        if self._flags is None:
            try:
                self._flags = int(self._gdbValue["flags"])
            except gdb.MemoryError:
                pass

        return self._flags

    @property
    def non_contiguous(self):
        if self._non_contiguous is None:
            flags = self.flags
            if flags is not None:
                self._non_contiguous = bool(flags & ptmalloc.NONCONTIGUOUS_BIT)

        return self._non_contiguous

    @property
    def have_fastchunks(self):
        if self._have_fastchunks is None:
            try:
                self._have_fastchunks = int(self._gdbValue["have_fastchunks"])
            except gdb.MemoryError:
                pass

        return self._have_fastchunks

    @property
    def top(self):
        if self._top is None:
            try:
                self._top = int(self._gdbValue["top"])
            except gdb.MemoryError:
                pass

        return self._top

    @property
    def fastbinsY(self):
        if self._fastbinsY is None:
            try:
                self._fastbinsY = []
                for i in range(NFASTBINS):
                    self._fastbinsY.append(int(self._gdbValue["fastbinsY"][i]))
            except gdb.MemoryError:
                pass

        return self._fastbinsY

    @property
    def bins(self):
        if self._bins is None:
            try:
                self._bins = []
                for i in range(NBINS):
                    self._bins.append(int(self._gdbValue["bins"][i]))
            except gdb.MemoryError:
                pass

        return self._bins

    @property
    def binmap(self):
        if self._binmap is None:
            try:
                self._binmap = []
                for i in range(BINMAPSIZE):
                    self._binmap.append(int(self._gdbValue["binmap"][i]))
            except gdb.MemoryError:
                pass

        return self._binmap

    @property
    def next(self):
        if self._next is None:
            try:
                self._next = int(self._gdbValue["next"])
            except gdb.MemoryError:
                pass

        return self._next

    @property
    def next_free(self):
        if self._next_free is None:
            try:
                self._next_free = int(self._gdbValue["next_free"])
            except gdb.MemoryError:
                pass

        return self._next_free

    @property
    def system_mem(self):
        if self._system_mem is None:
            try:
                self._system_mem = int(self._gdbValue["system_mem"])
            except gdb.MemoryError:
                pass

        return self._system_mem

    @property
    def active_heap(self):
        if self._active_heap is None:
            self._active_heap = Heap(self.top, arena=self)

        return self._active_heap

    @property
    def heaps(self):
        if self._heaps is None:
            heap = self.active_heap
            heap_list = [heap]
            if self.is_main_arena:
                sbrk_region = pwndbg.heap.current.get_sbrk_heap_region()
                if self.top not in sbrk_region:
                    heap_list.append(Heap(sbrk_region.start, arena=self))
            else:
                while heap.prev:
                    heap = Heap(heap.prev, arena=self)
                    heap_list.append(heap)

            heap_list.reverse()
            self._heaps = heap_list

        return self._heaps

    def fastbins(self):
        size = pwndbg.gdblib.arch.ptrsize * 2
        fd_offset = pwndbg.gdblib.arch.ptrsize * 2
        safe_lnk = pwndbg.glibc.check_safe_linking()
        result = Bins(BinType.FAST)
        for i in range(7):
            size += pwndbg.gdblib.arch.ptrsize * 2
            chain = pwndbg.chain.get(
                int(self.fastbinsY[i]),
                offset=fd_offset,
                limit=heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result.bins[size] = chain
        return result

    def __str__(self) -> str:
        prefix = "[%%%ds]    " % (pwndbg.gdblib.arch.ptrsize * 2)
        prefix_len = len(prefix % (""))
        res = [message.hint(prefix % hex(self.address)) + str(self.heaps[0])]
        for h in self.heaps[1:]:
            res.append(" " * prefix_len + str(h))

        return "\n".join(res)


class GlibcMemoryAllocator(pwndbg.heap.heap.MemoryAllocator):
    def __init__(self) -> None:
        # Global ptmalloc objects
        self._global_max_fast_addr: int = None
        self._global_max_fast: int = None
        self._main_arena_addr: int = None
        self._main_arena: Arena = None
        self._mp_addr: int = None
        self._mp = None
        # List of arenas/heaps
        self._arenas = None
        # ptmalloc cache for current thread
        self._thread_cache: gdb.Value = None

    def can_be_resolved(self):
        raise NotImplementedError()

    @property
    def main_arena(self):
        raise NotImplementedError()

    @property
    @pwndbg.lib.memoize.reset_on_stop
    def arenas(self):
        """Return a tuple of all current arenas."""
        arenas = []
        main_arena = self.main_arena
        arenas.append(main_arena)

        arena = main_arena
        addr = arena.next
        while addr != main_arena.address:
            arenas.append(Arena(addr))
            arena = Arena(addr)
            addr = arena.next

        arenas = tuple(arenas)
        self._arenas = arenas
        return arenas

    def has_tcache(self):
        raise NotImplementedError()

    @property
    def thread_arena(self):
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
    @pwndbg.lib.memoize.reset_on_thread
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

    def get_tcache(self, tcache_addr=None):
        raise NotImplementedError()

    def get_sbrk_heap_region(self):
        raise NotImplementedError()

    def get_region(self, addr):
        """Find the memory map containing 'addr'."""
        return copy.deepcopy(pwndbg.gdblib.vmmap.find(addr))

    def get_bins(self, bin_type, addr=None):
        if bin_type == BinType.TCACHE:
            return self.tcachebins(addr)
        elif bin_type == BinType.FAST:
            return self.fastbins(addr)
        elif bin_type == BinType.UNSORTED:
            return self.unsortedbin(addr)
        elif bin_type == BinType.SMALL:
            return self.smallbins(addr)
        elif bin_type == BinType.LARGE:
            return self.largebins(addr)
        else:
            return None

    def fastbin_index(self, size):
        if pwndbg.gdblib.arch.ptrsize == 8:
            return (size >> 4) - 2
        else:
            return (size >> 3) - 2

    def fastbins(self, arena_addr=None):
        """Returns: chain or None"""
        if arena_addr:
            arena = Arena(arena_addr)
        else:
            arena = self.thread_arena

        if arena is None:
            return

        fastbinsY = arena.fastbinsY
        fd_offset = self.chunk_key_offset("fd")
        num_fastbins = 7
        size = pwndbg.gdblib.arch.ptrsize * 2
        safe_lnk = pwndbg.glibc.check_safe_linking()

        result = Bins(BinType.FAST)
        for i in range(num_fastbins):
            size += pwndbg.gdblib.arch.ptrsize * 2
            chain = pwndbg.chain.get(
                int(fastbinsY[i]),
                offset=fd_offset,
                limit=heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result.bins[size] = Bin(chain)
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

        result = Bins(BinType.TCACHE)
        for i in range(num_tcachebins):
            size = self._request2size(tidx2usize(i))
            count = int(counts[i])
            chain = pwndbg.chain.get(
                int(entries[i]),
                offset=self.tcache_next_offset,
                limit=heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result.bins[size] = Bin(chain, count=count)
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

        if arena_addr is not None:
            arena = Arena(arena_addr)
        else:
            arena = self.thread_arena

        if arena is None:
            return

        normal_bins = arena._gdbValue["bins"]  # Breaks encapsulation, find a better way.

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
        result = Bins(BinType.UNSORTED)

        if chain is None:
            return

        fd_chain, bk_chain, is_corrupted = chain
        result.bins["all"] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)
        return result

    def smallbins(self, arena_addr=None):
        size = self.min_chunk_size - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = Bins(BinType.SMALL)
        for index in range(2, 64):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            fd_chain, bk_chain, is_corrupted = chain
            result.bins[size] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)
        return result

    def largebins(self, arena_addr=None):
        size = (ptmalloc.NSMALLBINS * self.malloc_alignment) - self.malloc_alignment
        spaces_table = self._spaces_table()

        result = Bins(BinType.LARGE)
        for index in range(64, 127):
            size += spaces_table[index]
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return

            fd_chain, bk_chain, is_corrupted = chain
            result.bins[self.largebin_index(size) - NSMALLBINS] = Bin(
                fd_chain, bk_chain, is_corrupted=is_corrupted
            )

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

    def is_statically_linked(self) -> bool:
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


class DebugSymsHeap(GlibcMemoryAllocator):
    can_be_resolved = GlibcMemoryAllocator.libc_has_debug_syms

    @property
    def main_arena(self):
        self._main_arena_addr = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "main_arena"
        ) or pwndbg.gdblib.symbol.address("main_arena")
        if self._main_arena_addr is not None:
            self._main_arena = Arena(self._main_arena_addr)

        return self._main_arena

    def has_tcache(self):
        return self.mp and "tcache_bins" in self.mp.type.keys() and self.mp["tcache_bins"]

    @property
    def thread_arena(self):
        if self.multithreaded:
            thread_arena_addr = pwndbg.gdblib.symbol.static_linkage_symbol_address(
                "thread_arena"
            ) or pwndbg.gdblib.symbol.address("thread_arena")
            if thread_arena_addr is not None and thread_arena_addr != 0:
                return Arena(pwndbg.gdblib.memory.pvoid(thread_arena_addr))
            else:
                return None
        else:
            return self.main_arena

    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. If it doesn't have one, use the main
        thread's tcache.
        """
        if self.has_tcache():
            tcache = self.get_sbrk_heap_region().vaddr + 0x10
            if self.multithreaded:
                tcache_addr = pwndbg.gdblib.memory.pvoid(
                    pwndbg.gdblib.symbol.static_linkage_symbol_address("tcache")
                    or pwndbg.gdblib.symbol.address("tcache")
                )
                if tcache_addr != 0:
                    tcache = tcache_addr

            try:
                self._thread_cache = pwndbg.gdblib.memory.poi(self.tcache_perthread_struct, tcache)
                self._thread_cache["entries"].fetch_lazy()
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
        return pwndbg.gdblib.memory.poi(self.heap_info, heap_for_ptr(addr))

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return pwndbg.gdblib.memory.poi(self.tcache_perthread_struct, tcache_addr)

    def get_sbrk_heap_region(self):
        """Return a Page object representing the sbrk heap region.
        Ensure the region's start address is aligned to SIZE_SZ * 2,
        which compensates for the presence of GLIBC_TUNABLES.
        """
        sbrk_base = pwndbg.lib.memory.align_up(
            int(self.mp["sbrk_base"]), pwndbg.heap.current.size_sz * 2
        )

        sbrk_region = self.get_region(sbrk_base)
        sbrk_region.memsz = sbrk_region.end - sbrk_base
        sbrk_region.vaddr = sbrk_base

        return sbrk_region

    def is_initialized(self):
        addr = pwndbg.gdblib.symbol.address("__libc_malloc_initialized")
        if addr is None:
            addr = pwndbg.gdblib.symbol.address("__malloc_initialized")
        return pwndbg.gdblib.memory.s32(addr) > 0


class SymbolUnresolvableError(Exception):
    def __init__(self, symbol) -> None:
        super().__init__(f"`{symbol}` can not be resolved via heuristic")
        self.symbol = symbol


class HeuristicHeap(GlibcMemoryAllocator):
    def __init__(self) -> None:
        super().__init__()
        self._structs_module = None

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

    def can_be_resolved(self) -> bool:
        return self.struct_module is not None

    @property
    def main_arena(self):
        main_arena_via_config = int(str(pwndbg.gdblib.config.main_arena), 0)
        main_arena_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "main_arena"
        ) or pwndbg.gdblib.symbol.address("main_arena")
        if main_arena_via_config or main_arena_via_symbol:
            self._main_arena_addr = main_arena_via_config or main_arena_via_symbol

        if not self._main_arena_addr:
            if self.is_statically_linked():
                section = pwndbg.gdblib.proc.dump_elf_data_section()
                section_address = pwndbg.gdblib.proc.get_data_section_address()
            else:
                section = pwndbg.glibc.dump_elf_data_section()
                section_address = pwndbg.glibc.get_data_section_address()
            if section and section_address:
                data_section_offset, size, data = section

                # try to find the default main_arena struct in the .data section
                for i in range(size - self.malloc_state.sizeof):
                    # https://github.com/bminor/glibc/blob/glibc-2.37/malloc/malloc.c#L1902-L1907
                    # static struct malloc_state main_arena =
                    # {
                    #   .mutex = _LIBC_LOCK_INITIALIZER,
                    #   .next = &main_arena,
                    #   .attached_threads = 1
                    # };
                    expected = self.malloc_state._c_struct()
                    expected.next = data_section_offset + i
                    expected.attached_threads = 1
                    expected = bytes(expected)
                    if expected == data[i : i + len(expected)]:
                        self._main_arena_addr = section_address + i
                        break

        if pwndbg.gdblib.memory.is_readable_address(self._main_arena_addr):
            self._main_arena = Arena(self._main_arena_addr)
            return self._main_arena

        raise SymbolUnresolvableError("main_arena")

    def has_tcache(self):
        # TODO/FIXME: Can we determine the tcache_bins existence more reliable?

        # There is no debug symbols, we determine the tcache_bins existence by checking glibc version only
        return self.is_initialized() and pwndbg.glibc.get_version() >= (2, 26)

    @property
    def thread_arena(self):
        thread_arena_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "thread_arena"
        ) or pwndbg.gdblib.symbol.address("thread_arena")
        if thread_arena_via_symbol:
            thread_arena_addr = pwndbg.gdblib.memory.pvoid(thread_arena_via_symbol)
            return Arena(thread_arena_addr) if thread_arena_addr else None
        if self.main_arena.address != pwndbg.heap.current.main_arena.next or self.multithreaded:
            thread_arena_via_config = int(str(pwndbg.gdblib.config.thread_arena), 0)
            if thread_arena_via_config:
                return Arena(thread_arena_via_config)
            # If it's multi-threaded, we can't determine the thread_arena, user needs to specify it manually
            raise SymbolUnresolvableError("thread_arena")
        else:
            return self.main_arena

    @property
    def thread_cache(self):
        """Locate a thread's tcache struct. We try to find its address in Thread Local Storage (TLS) first,
        and if that fails, we guess it's at the first chunk of the heap.
        """
        if not self.has_tcache():
            print(message.warn("This version of GLIBC was not compiled with tcache support."))
            return None
        thread_cache_via_config = int(str(pwndbg.gdblib.config.tcache), 0)
        thread_cache_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "tcache"
        ) or pwndbg.gdblib.symbol.address("tcache")
        if thread_cache_via_config:
            self._thread_cache = self.tcache_perthread_struct(thread_cache_via_config)
            return self._thread_cache
        elif thread_cache_via_symbol:
            thread_cache_struct_addr = pwndbg.gdblib.memory.pvoid(thread_cache_via_symbol)
            if thread_cache_struct_addr:
                self._thread_cache = self.tcache_perthread_struct(int(thread_cache_struct_addr))
                return self._thread_cache

        # TODO: The result might be wrong if the arena is being shared by multiple threads
        arena = self.thread_arena
        ptr_size = pwndbg.gdblib.arch.ptrsize

        cursor = arena.active_heap.start

        # i686 alignment heuristic
        first_chunk_size = pwndbg.gdblib.arch.unpack(
            pwndbg.gdblib.memory.read(cursor + ptr_size, ptr_size)
        )
        if first_chunk_size == 0:
            cursor += ptr_size * 2

        self._thread_cache = self.tcache_perthread_struct(cursor + ptr_size * 2)

        return self._thread_cache

    @property
    def mp(self):
        mp_via_config = int(str(pwndbg.gdblib.config.mp), 0)
        mp_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "mp_"
        ) or pwndbg.gdblib.symbol.address("mp_")
        if mp_via_config or mp_via_symbol:
            self._mp_addr = mp_via_symbol

        if not self._mp_addr:
            if self.is_statically_linked():
                section = pwndbg.gdblib.proc.dump_elf_data_section()
                section_address = pwndbg.gdblib.proc.get_data_section_address()
            else:
                section = pwndbg.glibc.dump_elf_data_section()
                section_address = pwndbg.glibc.get_data_section_address()
            if section and section_address:
                _, _, data = section

                # try to find the default mp_ struct in the .data section
                found = data.find(bytes(self.struct_module.DEFAULT_MP_))
                if found != -1:
                    self._mp_addr = section_address + found

        if pwndbg.gdblib.memory.is_readable_address(self._mp_addr):
            self._mp = self.malloc_par(self._mp_addr)
            return self._mp

        raise SymbolUnresolvableError("mp_")

    @property
    def global_max_fast(self):
        global_max_fast_via_config = int(str(pwndbg.gdblib.config.global_max_fast), 0)
        global_max_fast_via_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
            "global_max_fast"
        ) or pwndbg.gdblib.symbol.address("global_max_fast")

        if global_max_fast_via_config or global_max_fast_via_symbol:
            self._global_max_fast_addr = global_max_fast_via_config or global_max_fast_via_symbol
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

    def get_tcache(self, tcache_addr=None):
        if tcache_addr is None:
            return self.thread_cache

        return self.tcache_perthread_struct(tcache_addr)

    def get_sbrk_heap_region(self):
        """Return a Page object representing the sbrk heap region.
        Ensure the region's start address is aligned to SIZE_SZ * 2,
        which compensates for the presence of GLIBC_TUNABLES.
        This heuristic version requires some sanity checks and may raise SymbolUnresolvableError
        if malloc's `mp_` struct can't be resolved.
        """
        # Initialize malloc's mp_ struct if necessary.
        if not self._mp_addr:
            try:
                self.mp
            except Exception:
                # Should only raise SymbolUnresolvableError, but the heuristic heap implementation is still buggy so catch all exceptions for now.
                pass

        if self._mp_addr:
            if self.get_region(self.mp.get_field_address("sbrk_base")) and self.get_region(
                self.mp["sbrk_base"]
            ):
                sbrk_base = pwndbg.lib.memory.align_up(
                    int(self.mp["sbrk_base"]), pwndbg.heap.current.size_sz * 2
                )

                sbrk_region = self.get_region(sbrk_base)
                sbrk_region.memsz = self.get_region(sbrk_base).end - sbrk_base
                sbrk_region.vaddr = sbrk_base

                return sbrk_region
            else:
                raise ValueError("mp_.sbrk_base is unmapped or points to unmapped memory.")
        else:
            raise SymbolUnresolvableError("mp_")

    def is_initialized(self):
        # TODO/FIXME: If main_arena['top'] is been modified to 0, this will not work.
        # try to use vmmap or main_arena.top to find the heap
        return any("[heap]" == x.objfile for x in pwndbg.gdblib.vmmap.get()) or (
            self.can_be_resolved() and self.main_arena.top != 0
        )
