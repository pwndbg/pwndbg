from __future__ import annotations

import copy
import importlib
import sys
import types
from collections import OrderedDict

if sys.version_info >= (3, 11):
    # Python 3.11, see https://docs.python.org/3/whatsnew/3.11.html#enum
    from enum import ReprEnum as Enum
else:
    from enum import Enum

import typing
from typing import Any
from typing import Callable
from typing import Dict
from typing import Generic
from typing import List
from typing import OrderedDict as OrderedDictType
from typing import Set
from typing import Tuple
from typing import Type
from typing import TypeVar

import pwndbg
import pwndbg.aglib.heap
import pwndbg.aglib.heap.heap
import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.aglib.symbol
import pwndbg.aglib.tls
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.glibc
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.search
from pwndbg.color import message
from pwndbg.color.memory import c as M

PREV_INUSE = 1
IS_MMAPPED = 2
NON_MAIN_ARENA = 4
SIZE_BITS = PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA
NONCONTIGUOUS_BIT = 2

NBINS = 128
NSMALLBINS = 64

# The `pwndbg.aglib.heap.structs` module is only imported at runtime when
# the heap heuristics are used in `HeuristicHeap.struct_module` and
# uses runtime information to select the correct structs.
# Only import it globally during static type checking.
if typing.TYPE_CHECKING:
    import pwndbg.aglib.heap.structs

    TheType = TypeVar(
        "TheType", pwndbg.dbg_mod.Type, typing.Type[pwndbg.aglib.heap.structs.CStruct2GDB]
    )
    TheValue = TypeVar("TheValue", pwndbg.dbg_mod.Value, pwndbg.aglib.heap.structs.CStruct2GDB)
else:
    TheType = TypeVar("TheType")
    TheValue = TypeVar("TheValue")

# We defer the initialization of HEAP_MAX_SIZE, as it needs the value of
# `pwndbg.aglib.arch.ptrsize`, which might not always be available at this
# point. See `heap_for_ptr`.
HEAP_MAX_SIZE: int = None

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

    def valid_fields(self) -> List[str]:
        if self in [BinType.FAST, BinType.TCACHE]:
            return ["fd"]
        elif self in [BinType.SMALL, BinType.UNSORTED]:
            return ["fd", "bk"]
        elif self == BinType.LARGE:
            return ["fd", "bk", "fd_nextsize", "bk_nextsize"]
        else:  # BinType.NOT_IN_BIN
            return []


class Bin:
    def __init__(
        self,
        fd_chain: List[int],
        bk_chain: List[int] | None = None,
        count: int | None = None,
        is_corrupted: bool = False,
    ) -> None:
        self.fd_chain = fd_chain
        self.bk_chain = bk_chain
        self.count = count
        self.is_corrupted = is_corrupted

    def contains_chunk(self, chunk: int) -> bool:
        return chunk in self.fd_chain

    @staticmethod
    def size_to_display_name(size: int | str) -> str:
        if isinstance(size, str) and size == "all":
            return size

        assert isinstance(size, int)

        return hex(size)


class Bins:
    def __init__(self, bin_type: BinType) -> None:
        self.bins: OrderedDictType[int | str, Bin] = OrderedDict()
        self.bin_type = bin_type

    # TODO: There's a bunch of bin-specific logic in here, maybe we should
    # subclass and put that logic in there
    def contains_chunk(self, size: int, chunk: int):
        # TODO: It will be the same thing, but it would be better if we used
        # pwndbg.aglib.heap.current.size_sz. I think each bin should already have a
        # reference to the allocator and shouldn't need to access the `current`
        # variable
        ptr_size = pwndbg.aglib.arch.ptrsize

        if self.bin_type == BinType.UNSORTED:
            # The unsorted bin only has one bin called 'all'

            # TODO: We shouldn't be mixing int and str types like this
            size = "all"  # type: ignore[assignment]
        elif self.bin_type == BinType.LARGE:
            # All the other bins (other than unsorted) store chunks of the same
            # size in a bin, so we can use the size directly. But the largebin
            # stores a range of sizes, so we need to compute which bucket this
            # chunk falls into

            # TODO: Refactor this, the bin should know how to calculate
            # largebin_index without calling into the allocator
            assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
            size = pwndbg.aglib.heap.current.largebin_index(size) - NSMALLBINS

        elif self.bin_type == BinType.TCACHE:
            # Unlike fastbins, tcache bins don't store the chunk address in the
            # bins, they store the address of the fd pointer, so we need to
            # search for that address in the tcache bin instead

            # TODO: Can we use chunk_key_offset?
            chunk += ptr_size * 2

        if size in self.bins:
            return self.bins[size].contains_chunk(chunk)

        return False


def heap_for_ptr(ptr: int) -> int:
    """Round a pointer to a chunk down to find its corresponding heap_info
    struct, the pointer must point inside a heap which does not belong to
    the main arena.
    """
    # See https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/arena.c;h=37183cfb6ab5d0735cc82759626670aff3832cd0;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l30
    # and https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f8e7250f70f6f26b0acb5901bcc4f6e39a8a52b2;hb=086ee48eaeaba871a2300daf85469671cc14c7e9#l869
    # 1 Mb (x86) or 64 Mb (x64)
    global HEAP_MAX_SIZE
    if HEAP_MAX_SIZE is None:
        HEAP_MAX_SIZE = 1024 * 1024 if pwndbg.aglib.arch.ptrsize == 4 else 2 * 4 * 1024 * 1024 * 8

    return ptr & ~(HEAP_MAX_SIZE - 1)


class ChunkField(int, Enum):
    PREV_SIZE = 1
    SIZE = 2
    FD = 3
    BK = 4
    FD_NEXTSIZE = 5
    BK_NEXTSIZE = 6


def fetch_chunk_metadata(address: int, include_only_fields: Set[ChunkField] | None = None):
    prev_size_field_name = pwndbg.aglib.memory.resolve_renamed_struct_field(
        "malloc_chunk", {"prev_size", "mchunk_prev_size"}
    )
    size_field_name = pwndbg.aglib.memory.resolve_renamed_struct_field(
        "malloc_chunk", {"size", "mchunk_size"}
    )

    if include_only_fields is None:
        fetched_struct = pwndbg.aglib.memory.fetch_struct_as_dictionary("malloc_chunk", address)
    else:
        requested_fields: Set[str] = set()

        for field in include_only_fields:
            if field is ChunkField.PREV_SIZE:
                requested_fields.add(prev_size_field_name)
            elif field is ChunkField.SIZE:
                requested_fields.add(size_field_name)
            elif field is ChunkField.FD:
                requested_fields.add("fd")
            elif field is ChunkField.BK:
                requested_fields.add("bk")
            elif field is ChunkField.FD_NEXTSIZE:
                requested_fields.add("fd_nextsize")
            elif field is ChunkField.BK_NEXTSIZE:
                requested_fields.add("bk_nextsize")

        fetched_struct = pwndbg.aglib.memory.fetch_struct_as_dictionary(
            "malloc_chunk", address, include_only_fields=requested_fields
        )

    normalized_struct = {}
    for field in fetched_struct:
        if field == prev_size_field_name:
            normalized_struct[ChunkField.PREV_SIZE] = fetched_struct[prev_size_field_name]
        elif field == size_field_name:
            normalized_struct[ChunkField.SIZE] = fetched_struct[size_field_name]
        elif field == "fd":
            normalized_struct[ChunkField.FD] = fetched_struct["fd"]
        elif field == "bk":
            normalized_struct[ChunkField.BK] = fetched_struct["bk"]
        elif field == "fd_nextsize":
            normalized_struct[ChunkField.FD_NEXTSIZE] = fetched_struct["fd_nextsize"]
        elif field == "bk_nextsize":
            normalized_struct[ChunkField.BK_NEXTSIZE] = fetched_struct["bk_nextsize"]

    return normalized_struct


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

    def __init__(self, addr: int, heap: Heap | None = None, arena: Arena | None = None) -> None:
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        assert pwndbg.aglib.heap.current.malloc_chunk is not None
        if isinstance(pwndbg.aglib.heap.current.malloc_chunk, pwndbg.dbg_mod.Type):
            self._gdbValue = pwndbg.aglib.memory.get_typed_pointer_value(
                pwndbg.aglib.heap.current.malloc_chunk, addr
            )
        else:
            self._gdbValue = pwndbg.aglib.heap.current.malloc_chunk(addr)
        self.address = int(self._gdbValue.address)
        self._prev_size: int | None = None
        self._size: int | None = None
        self._real_size: int | None = None
        self._flags: Dict[str, bool] | None = None
        self._non_main_arena: bool | None = None
        self._is_mmapped: bool | None = None
        self._prev_inuse: bool | None = None
        self._fd = None
        self._bk = None
        self._fd_nextsize = None
        self._bk_nextsize = None
        self._heap = heap
        self._arena = arena
        self._is_top_chunk: bool | None = None

    # Some chunk fields were renamed in GLIBC 2.25 master branch.
    def __match_renamed_field(self, field: str):
        field_renames = {
            "size": ["size", "mchunk_size"],
            "prev_size": ["prev_size", "mchunk_prev_size"],
        }

        for field_name in field_renames[field]:
            if self._gdbValue.type.has_field(field_name):
                return field_name

        raise ValueError(f"Chunk field name did not match any of {field_renames[field]}.")

    @property
    def prev_size(self) -> int | None:
        if self._prev_size is None:
            try:
                self._prev_size = int(self._gdbValue[self.__match_renamed_field("prev_size")])
            except pwndbg.dbg_mod.Error:
                pass

        return self._prev_size

    @property
    def size(self) -> int | None:
        if self._size is None:
            try:
                self._size = int(self._gdbValue[self.__match_renamed_field("size")])
            except pwndbg.dbg_mod.Error:
                pass

        return self._size

    @property
    def real_size(self) -> int | None:
        if self._real_size is None:
            try:
                self._real_size = int(self._gdbValue[self.__match_renamed_field("size")]) & ~(
                    SIZE_BITS
                )
            except pwndbg.dbg_mod.Error:
                pass

        return self._real_size

    @property
    def flags(self) -> Dict[str, bool] | None:
        if self._flags is None:
            if (
                self.size is not None
                and self.non_main_arena is not None
                and self.is_mmapped is not None
                and self.prev_inuse is not None
            ):
                self._flags = {
                    "non_main_arena": self.non_main_arena,
                    "is_mmapped": self.is_mmapped,
                    "prev_inuse": self.prev_inuse,
                }

        return self._flags

    @property
    def non_main_arena(self) -> bool | None:
        if self._non_main_arena is None:
            sz = self.size
            if sz is not None:
                self._non_main_arena = bool(sz & NON_MAIN_ARENA)

        return self._non_main_arena

    @property
    def is_mmapped(self) -> bool | None:
        if self._is_mmapped is None:
            sz = self.size
            if sz is not None:
                self._is_mmapped = bool(sz & IS_MMAPPED)

        return self._is_mmapped

    @property
    def prev_inuse(self) -> bool | None:
        if self._prev_inuse is None:
            sz = self.size
            if sz is not None:
                self._prev_inuse = bool(sz & PREV_INUSE)

        return self._prev_inuse

    @property
    def fd(self):
        if self._fd is None:
            try:
                self._fd = int(self._gdbValue["fd"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._fd

    @property
    def bk(self):
        if self._bk is None:
            try:
                self._bk = int(self._gdbValue["bk"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._bk

    @property
    def fd_nextsize(self):
        if self._fd_nextsize is None:
            try:
                self._fd_nextsize = int(self._gdbValue["fd_nextsize"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._fd_nextsize

    @property
    def bk_nextsize(self):
        if self._bk_nextsize is None:
            try:
                self._bk_nextsize = int(self._gdbValue["bk_nextsize"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._bk_nextsize

    @property
    def heap(self) -> Heap:
        if self._heap is None:
            self._heap = Heap(self.address)

        return self._heap

    @property
    def arena(self) -> Arena | None:
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

        if self.real_size is None or self.real_size == 0:
            return None

        next = Chunk(self.address + self.real_size, arena=self.arena)
        if pwndbg.aglib.memory.is_readable_address(next.address):
            return next
        else:
            return None

    def __contains__(self, addr: int) -> bool:
        """
        This allow us to avoid extra constructions like 'if start_addr <= ptr < end_addr', etc.
        """
        size_field_address = int(self._gdbValue[self.__match_renamed_field("size")].address)
        start_address = size_field_address if self.prev_inuse else self.address

        next = self.next_chunk()
        # and this is handles chunk's last qword field, depending on prev_inuse bit
        if next is None:
            end_address = size_field_address + self.real_size
        else:
            next_size_field_address = int(
                next._gdbValue[self.__match_renamed_field("size")].address
            )
            end_address = next_size_field_address if next.prev_inuse else next.address

        return start_address <= addr < end_address


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

    start: int
    end: int

    def __init__(self, addr: int, arena: Arena | None = None) -> None:
        """Build a Heap object given an address on that heap.
        Heap regions are treated differently depending on their arena:
        1) main_arena - uses the sbrk heap
        2) non-main arena - heap starts after its heap_info struct (and possibly an arena)
        3) non-contiguous main_arena - just a memory region
        4) no arena - for fake/mmapped chunks
        """
        allocator = pwndbg.aglib.heap.current
        assert isinstance(allocator, GlibcMemoryAllocator)
        main_arena = allocator.main_arena

        sbrk_region = allocator.get_sbrk_heap_region()
        if sbrk_region is not None and addr in sbrk_region:
            # Case 1; main_arena.
            self.arena = main_arena if arena is None else arena
            self._memory_region = sbrk_region
            self._gdbValue = None
        else:
            heap_region = allocator.get_region(addr)
            if heap_region is None:
                raise ValueError(f"Cannot build heap object on an unmapped address ({hex(addr)})")

            heap_info = allocator.get_heap(addr)
            try:
                ar_ptr = int(heap_info["ar_ptr"])
            except pwndbg.dbg_mod.Error:
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
        # i686 alignment heuristic
        if Chunk(self.start).size == 0:
            self.start += pwndbg.aglib.arch.ptrsize * 2
        self.end = self._memory_region.end
        self.first_chunk = Chunk(self.start)

        self._prev = None

    @property
    def prev(self):
        if self._prev is None and self._gdbValue is not None:
            try:
                self._prev = int(self._gdbValue["prev"])
            except pwndbg.dbg_mod.Error:
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
        fmt = "[%%%ds]" % (pwndbg.aglib.arch.ptrsize * 2)
        return message.hint(fmt % (hex(self.first_chunk.address))) + M.heap(
            str(pwndbg.aglib.vmmap.find(self.start))
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

    def __init__(self, addr: int) -> None:
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        assert pwndbg.aglib.heap.current.malloc_state is not None
        if isinstance(pwndbg.aglib.heap.current.malloc_state, pwndbg.dbg_mod.Type):
            self._gdbValue = pwndbg.aglib.memory.get_typed_pointer_value(
                pwndbg.aglib.heap.current.malloc_state, addr
            )
        else:
            self._gdbValue = pwndbg.aglib.heap.current.malloc_state(addr)

        self.address = int(self._gdbValue.address)
        self._is_main_arena: bool | None = None
        self._top = None
        self._active_heap = None
        self._heaps = None
        self._mutex = None
        self._flags = None
        self._non_contiguous = None
        self._have_fastchunks = None
        self._fastbinsY: List[int] | None = None
        self._bins: List[int] | None = None
        self._binmap: List[int] | None = None
        self._next: int | None = None
        self._next_free: int | None = None
        self._system_mem = None

    @property
    def is_main_arena(self) -> bool:
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        if self._is_main_arena is None:
            self._is_main_arena = (
                pwndbg.aglib.heap.current.main_arena is not None
                and self.address == pwndbg.aglib.heap.current.main_arena.address
            )

        return self._is_main_arena

    @property
    def mutex(self) -> int | None:
        if self._mutex is None:
            try:
                self._mutex = int(self._gdbValue["mutex"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._mutex

    @property
    def flags(self) -> int | None:
        if self._flags is None:
            try:
                self._flags = int(self._gdbValue["flags"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._flags

    @property
    def non_contiguous(self) -> bool | None:
        if self._non_contiguous is None:
            flags = self.flags
            if flags is not None:
                self._non_contiguous = bool(flags & NONCONTIGUOUS_BIT)

        return self._non_contiguous

    @property
    def have_fastchunks(self) -> int | None:
        if self._have_fastchunks is None:
            try:
                self._have_fastchunks = int(self._gdbValue["have_fastchunks"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._have_fastchunks

    @property
    def top(self) -> int | None:
        if self._top is None:
            try:
                self._top = int(self._gdbValue["top"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._top

    @property
    def fastbinsY(self) -> List[int]:
        if self._fastbinsY is None:
            self._fastbinsY = []
            try:
                for i in range(NFASTBINS):
                    self._fastbinsY.append(int(self._gdbValue["fastbinsY"][i]))
            except pwndbg.dbg_mod.Error:
                pass

        return self._fastbinsY

    @property
    def bins(self) -> List[int]:
        if self._bins is None:
            self._bins = []
            try:
                for i in range(NBINS):
                    self._bins.append(int(self._gdbValue["bins"][i]))
            except pwndbg.dbg_mod.Error:
                pass

        return self._bins

    @property
    def binmap(self) -> List[int]:
        if self._binmap is None:
            self._binmap = []
            try:
                for i in range(BINMAPSIZE):
                    self._binmap.append(int(self._gdbValue["binmap"][i]))
            except pwndbg.dbg_mod.Error:
                pass

        return self._binmap

    @property
    def next(self) -> int | None:
        if self._next is None:
            try:
                self._next = int(self._gdbValue["next"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._next

    @property
    def next_free(self) -> int | None:
        if self._next_free is None:
            try:
                self._next_free = int(self._gdbValue["next_free"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._next_free

    @property
    def system_mem(self) -> int | None:
        if self._system_mem is None:
            try:
                self._system_mem = int(self._gdbValue["system_mem"])
            except pwndbg.dbg_mod.Error:
                pass

        return self._system_mem

    @property
    def active_heap(self) -> Heap:
        if self._active_heap is None:
            self._active_heap = Heap(self.top, arena=self)

        return self._active_heap

    @property
    def heaps(self):
        if self._heaps is None:
            heap = self.active_heap
            heap_list = [heap]
            if self.is_main_arena:
                assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
                sbrk_region = pwndbg.aglib.heap.current.get_sbrk_heap_region()
                if self.top not in sbrk_region:
                    heap_list.append(Heap(sbrk_region.start, arena=self))
            else:
                while heap.prev:
                    heap = Heap(heap.prev, arena=self)
                    heap_list.append(heap)

            heap_list.reverse()
            self._heaps = heap_list

        return self._heaps

    def fastbins(self) -> Bins:
        size = pwndbg.aglib.arch.ptrsize * 2
        fd_offset = pwndbg.aglib.arch.ptrsize * 2
        safe_lnk = pwndbg.glibc.check_safe_linking()
        result = Bins(BinType.FAST)
        for i in range(NFASTBINS):
            size += pwndbg.aglib.arch.ptrsize * 2
            chain = pwndbg.chain.get(
                int(self.fastbinsY[i]),
                offset=fd_offset,
                limit=pwndbg.aglib.heap.heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result.bins[size] = Bin(chain)
        return result

    def __str__(self) -> str:
        prefix = "[%%%ds]    " % (pwndbg.aglib.arch.ptrsize * 2)
        prefix_len = len(prefix % (""))
        res = [message.hint(prefix % hex(self.address)) + str(self.heaps[0])]
        for h in self.heaps[1:]:
            res.append(" " * prefix_len + str(h))

        return "\n".join(res)


class GlibcMemoryAllocator(pwndbg.aglib.heap.heap.MemoryAllocator, Generic[TheType, TheValue]):
    # Largebin reverse lookup tables.
    # These help determine the range of chunk sizes that each largebin can hold.
    # They were generated by running every chunk size between the minimum & maximum large chunk
    # sizes through largebin_index().
    # Largebin 31 (bin 95) isn't used on i386 when MALLOC_ALIGNMENT is 16, so its value must be added manually.
    largebin_reverse_lookup_32 = (
        0x200,
        0x240,
        0x280,
        0x2C0,
        0x300,
        0x340,
        0x380,
        0x3C0,
        0x400,
        0x440,
        0x480,
        0x4C0,
        0x500,
        0x540,
        0x580,
        0x5C0,
        0x600,
        0x640,
        0x680,
        0x6C0,
        0x700,
        0x740,
        0x780,
        0x7C0,
        0x800,
        0x840,
        0x880,
        0x8C0,
        0x900,
        0x940,
        0x980,
        0x9C0,
        0xA00,
        0xC00,
        0xE00,
        0x1000,
        0x1200,
        0x1400,
        0x1600,
        0x1800,
        0x1A00,
        0x1C00,
        0x1E00,
        0x2000,
        0x2200,
        0x2400,
        0x2600,
        0x2800,
        0x2A00,
        0x3000,
        0x4000,
        0x5000,
        0x6000,
        0x7000,
        0x8000,
        0x9000,
        0xA000,
        0x10000,
        0x18000,
        0x20000,
        0x28000,
        0x40000,
        0x80000,
    )

    largebin_reverse_lookup_32_big = (
        0x3F0,
        0x400,
        0x440,
        0x480,
        0x4C0,
        0x500,
        0x540,
        0x580,
        0x5C0,
        0x600,
        0x640,
        0x680,
        0x6C0,
        0x700,
        0x740,
        0x780,
        0x7C0,
        0x800,
        0x840,
        0x880,
        0x8C0,
        0x900,
        0x940,
        0x980,
        0x9C0,
        0xA00,
        0xA40,
        0xA80,
        0xAC0,
        0xB00,
        0xB40,
        0xB80,  # Largebin 31 (bin 95) is unused, but its size is used to calculate the previous bin's maximum chunk size.
        0xB80,
        0xC00,
        0xE00,
        0x1000,
        0x1200,
        0x1400,
        0x1600,
        0x1800,
        0x1A00,
        0x1C00,
        0x1E00,
        0x2000,
        0x2200,
        0x2400,
        0x2600,
        0x2800,
        0x2A00,
        0x3000,
        0x4000,
        0x5000,
        0x6000,
        0x7000,
        0x8000,
        0x9000,
        0xA000,
        0x10000,
        0x18000,
        0x20000,
        0x28000,
        0x40000,
        0x80000,
    )

    largebin_reverse_lookup_64 = (
        0x400,
        0x440,
        0x480,
        0x4C0,
        0x500,
        0x540,
        0x580,
        0x5C0,
        0x600,
        0x640,
        0x680,
        0x6C0,
        0x700,
        0x740,
        0x780,
        0x7C0,
        0x800,
        0x840,
        0x880,
        0x8C0,
        0x900,
        0x940,
        0x980,
        0x9C0,
        0xA00,
        0xA40,
        0xA80,
        0xAC0,
        0xB00,
        0xB40,
        0xB80,
        0xBC0,
        0xC00,
        0xC40,
        0xE00,
        0x1000,
        0x1200,
        0x1400,
        0x1600,
        0x1800,
        0x1A00,
        0x1C00,
        0x1E00,
        0x2000,
        0x2200,
        0x2400,
        0x2600,
        0x2800,
        0x2A00,
        0x3000,
        0x4000,
        0x5000,
        0x6000,
        0x7000,
        0x8000,
        0x9000,
        0xA000,
        0x10000,
        0x18000,
        0x20000,
        0x28000,
        0x40000,
        0x80000,
    )

    def __init__(self) -> None:
        # Global ptmalloc objects
        self._global_max_fast_addr: int | None = None
        self._global_max_fast: int | None = None
        self._main_arena_addr: int | None = None
        self._main_arena: Arena | None = None
        self._mp_addr: int | None = None
        self._mp = None
        # List of arenas/heaps
        self._arenas = None
        # ptmalloc cache for current thread
        self._thread_cache: TheValue | None = None

    def largebin_reverse_lookup(self, index: int) -> int:
        """Pick the appropriate largebin_reverse_lookup_ function for this architecture."""
        if pwndbg.aglib.arch.ptrsize == 8:
            return self.largebin_reverse_lookup_64[index]
        elif self.malloc_alignment == 16:
            return self.largebin_reverse_lookup_32_big[index]
        else:
            return self.largebin_reverse_lookup_32[index]

    def largebin_size_range_from_index(self, index: int):
        largest_largebin = self.largebin_index(pwndbg.aglib.arch.ptrmask) - 64
        start_size = self.largebin_reverse_lookup(index)

        if index != largest_largebin:
            end_size = self.largebin_reverse_lookup(index + 1) - self.malloc_alignment
        else:
            end_size = pwndbg.aglib.arch.ptrmask

        return (start_size, end_size)

    def can_be_resolved(self) -> bool:
        raise NotImplementedError()

    @property
    def main_arena(self) -> Arena | None:
        raise NotImplementedError()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def arenas(self) -> Tuple[Arena, ...]:
        """Return a tuple of all current arenas."""
        arenas: List[Arena] = []
        main_arena = self.main_arena
        if main_arena:
            arenas.append(main_arena)

            arena = main_arena
            addr = arena.next
            while addr is not None and addr != main_arena.address:
                arena = Arena(addr)
                arenas.append(arena)
                addr = arena.next

        self._arenas = tuple(arenas)
        return self._arenas

    def has_tcache(self) -> bool:
        raise NotImplementedError()

    @property
    def thread_arena(self) -> Arena | None:
        raise NotImplementedError()

    @property
    def thread_cache(self) -> TheValue | None:
        raise NotImplementedError()

    @property
    def mp(self) -> TheValue | None:
        raise NotImplementedError()

    @property
    def global_max_fast(self) -> int | None:
        raise NotImplementedError()

    @property
    def heap_info(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def malloc_chunk(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def malloc_state(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def tcache_perthread_struct(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def tcache_entry(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def mallinfo(self) -> TheType | None:
        raise NotImplementedError()

    @property
    def malloc_par(self) -> TheType | None:
        raise NotImplementedError()

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_alignment(self) -> int:
        """Corresponds to MALLOC_ALIGNMENT in glibc malloc.c"""
        if pwndbg.aglib.arch.name == "i386" and pwndbg.glibc.get_version() >= (2, 26):
            # i386 will override it to 16 when GLIBC version >= 2.26
            # See https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/i386/malloc-alignment.h#L22
            return 16
        # See https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/generic/malloc-alignment.h#L27
        long_double_alignment = pwndbg.aglib.typeinfo.lookup_types("long double").alignof
        return (
            long_double_alignment if 2 * self.size_sz < long_double_alignment else 2 * self.size_sz
        )

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def size_sz(self) -> int:
        """Corresponds to SIZE_SZ in glibc malloc.c"""
        return pwndbg.aglib.arch.ptrsize

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_align_mask(self) -> int:
        """Corresponds to MALLOC_ALIGN_MASK in glibc malloc.c"""
        return self.malloc_alignment - 1

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def minsize(self) -> int:
        """Corresponds to MINSIZE in glibc malloc.c"""
        return self.min_chunk_size

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def min_chunk_size(self) -> int:
        """Corresponds to MIN_CHUNK_SIZE in glibc malloc.c"""
        return pwndbg.aglib.arch.ptrsize * 4

    @property
    @pwndbg.lib.cache.cache_until("objfile", "thread")
    def multithreaded(self) -> bool:
        """Is malloc operating within a multithreaded environment."""
        addr = pwndbg.aglib.symbol.lookup_symbol_addr("__libc_multiple_threads")
        if addr:
            return pwndbg.aglib.memory.s32(addr) > 0
        return len(pwndbg.dbg.selected_inferior().threads()) > 1

    def _request2size(self, req: int) -> int:
        """Corresponds to request2size in glibc malloc.c"""
        if req + self.size_sz + self.malloc_align_mask < self.minsize:
            return self.minsize
        return (req + self.size_sz + self.malloc_align_mask) & ~self.malloc_align_mask

    def chunk_flags(self, size: int) -> Tuple[int, int, int]:
        return (
            size & PREV_INUSE,
            size & IS_MMAPPED,
            size & NON_MAIN_ARENA,
        )

    def chunk_key_offset(self, key: str) -> int | None:
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
        if val is None:
            return None
        chunk_keys = [renames[key] if key in renames else key for key in val.keys()]
        try:
            return chunk_keys.index(key) * pwndbg.aglib.arch.ptrsize
        except Exception:
            return None

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def tcache_next_offset(self) -> int:
        return self.tcache_entry.keys().index("next") * pwndbg.aglib.arch.ptrsize

    def get_heap(self, addr: int) -> TheValue | None:
        raise NotImplementedError()

    def get_tcache(self, tcache_addr: int | None = None) -> TheValue | None:
        raise NotImplementedError()

    def get_sbrk_heap_region(self) -> pwndbg.lib.memory.Page | None:
        raise NotImplementedError()

    def get_region(self, addr: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
        """Find the memory map containing 'addr'."""
        return copy.deepcopy(pwndbg.aglib.vmmap.find(addr))

    def get_bins(self, bin_type: BinType, addr: int | None = None) -> Bins | None:
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

    def fastbin_index(self, size: int):
        if pwndbg.aglib.arch.ptrsize == 8:
            return (size >> 4) - 2
        else:
            return (size >> 3) - 2

    def fastbins(self, arena_addr: int | None = None) -> Bins | None:
        """Returns: chain or None"""
        if arena_addr:
            arena = Arena(arena_addr)
        else:
            arena = self.thread_arena

        if arena is None:
            return None

        return arena.fastbins()

    def tcachebins(self, tcache_addr: int | None = None) -> Bins | None:
        """Returns: tuple(chain, count) or None"""
        tcache = self.get_tcache(tcache_addr)

        if tcache is None:
            return None

        counts = tcache["counts"]
        entries = tcache["entries"]

        num_tcachebins = entries.type.sizeof // entries.type.target().sizeof
        safe_lnk = pwndbg.glibc.check_safe_linking()

        def tidx2usize(idx: int):
            """Tcache bin index to chunk size, following tidx2usize macro in glibc malloc.c"""
            return idx * self.malloc_alignment + self.minsize - self.size_sz

        result = Bins(BinType.TCACHE)
        for i in range(num_tcachebins):
            size = self._request2size(tidx2usize(i))
            count = int(counts[i])
            chain = pwndbg.chain.get(
                int(entries[i]),
                offset=self.tcache_next_offset,
                limit=pwndbg.aglib.heap.heap_chain_limit,
                safe_linking=safe_lnk,
            )

            result.bins[size] = Bin(chain, count=count)
        return result

    def check_chain_corrupted(self, chain_fd: List[int], chain_bk: List[int]) -> bool:
        """
        Checks if the doubly linked list (of a {unsorted, small, large} bin)
        defined by chain_fd, chain_bk is corrupted.

        Even if the chains do not cover the whole bin, they still are expected
        to be of the same length.

        Returns True if the bin is certainly corrupted, otherwise False.
        """

        if len(chain_fd) != len(chain_bk):
            # If the chain lengths aren't equal, the chain is corrupted
            # The vast majority of corruptions will be caught here
            return True
        elif len(chain_fd) < 2 or len(chain_bk) < 2:
            # Chains containing less than two entries are corrupted, as the smallest
            # chain (an empty bin) would look something like `[main_arena+88, 0]`.
            return True
        elif len(chain_fd) == len(chain_bk) == 2:
            # Check if the bin points to itself (is empty)

            if chain_fd != chain_bk:
                return True
            elif chain_fd[-1] != 0:
                return True
            else:
                bin_chk = Chunk(chain_fd[0])
                if not (bin_chk.fd == bin_chk.bk == chain_fd[0]):
                    return True

        else:
            chain_sz = len(chain_fd) - (1 if chain_fd[-1] == 0 else 0)

            # Forward and backward chains may have some overlap, we don't need to recheck those chunks
            checked = set()

            # Check connections in all chunks from the forward chain
            for i in range(chain_sz):
                chunk_addr = chain_fd[i]
                chunk = Chunk(chunk_addr)
                if chunk.fd is None or Chunk(chunk.fd).bk != chunk_addr:
                    return True
                if chunk.bk is None or Chunk(chunk.bk).fd != chunk_addr:
                    return True
                checked.add(chunk_addr)

            # Check connections in unchecked chunks from the backward chain
            for i in range(chain_sz):
                chunk_addr = chain_bk[i]
                if chunk_addr in checked:
                    # We don't need to check any more chunks
                    break
                chunk = Chunk(chunk_addr)
                if chunk.fd is None or Chunk(chunk.fd).bk != chunk_addr:
                    return True
                if chunk.bk is None or Chunk(chunk.bk).fd != chunk_addr:
                    return True

        return False

    def bin_at(
        self, index: int, arena_addr: int | None = None
    ) -> Tuple[List[int], List[int], bool] | None:
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
            return None

        normal_bins = arena._gdbValue["bins"]  # Breaks encapsulation, find a better way.

        bins_base = int(normal_bins.address) - (pwndbg.aglib.arch.ptrsize * 2)
        current_base = bins_base + (index * pwndbg.aglib.arch.ptrsize * 2)

        # check whether the bin is empty
        bin_chunk = Chunk(current_base)
        if bin_chunk.fd == bin_chunk.bk == current_base:
            return ([0], [0], False)

        front, back = normal_bins[index * 2], normal_bins[index * 2 + 1]
        fd_offset = self.chunk_key_offset("fd")
        bk_offset = self.chunk_key_offset("bk")

        chain_size = int(pwndbg.aglib.heap.heap_chain_limit)
        corrupt_chain_size = int(pwndbg.aglib.heap.heap_corruption_check_limit)

        get_chain = lambda bin, offset: pwndbg.chain.get(
            int(bin),
            offset=offset,
            hard_stop=current_base,
            limit=max(chain_size, corrupt_chain_size),
            include_start=True,
        )

        full_chain_fd = get_chain(front, fd_offset)
        full_chain_bk = get_chain(back, bk_offset)
        chain_fd = full_chain_fd[: (chain_size + 1)]
        chain_bk = full_chain_bk[: (chain_size + 1)]
        corrupt_chain_fd = full_chain_fd[: (corrupt_chain_size + 1)]
        corrupt_chain_bk = full_chain_bk[: (corrupt_chain_size + 1)]

        is_chain_corrupted = False
        if corrupt_chain_size > 1:
            is_chain_corrupted = self.check_chain_corrupted(corrupt_chain_fd, corrupt_chain_bk)

        return (chain_fd, chain_bk, is_chain_corrupted)

    def unsortedbin(self, arena_addr: int | None = None) -> Bins | None:
        chain = self.bin_at(1, arena_addr=arena_addr)
        result = Bins(BinType.UNSORTED)

        if chain is None:
            return None

        fd_chain, bk_chain, is_corrupted = chain
        result.bins["all"] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)
        return result

    def smallbins(self, arena_addr: int | None = None) -> Bins | None:
        size = self.min_chunk_size
        result = Bins(BinType.SMALL)
        for index in range(2, 64):
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return None

            fd_chain, bk_chain, is_corrupted = chain
            result.bins[size] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)
            size += self.malloc_alignment
        return result

    def largebins(self, arena_addr: int | None = None) -> Bins | None:
        result = Bins(BinType.LARGE)
        for index in range(64, 127):
            chain = self.bin_at(index, arena_addr=arena_addr)

            if chain is None:
                return None

            fd_chain, bk_chain, is_corrupted = chain
            result.bins[index - NSMALLBINS] = Bin(fd_chain, bk_chain, is_corrupted=is_corrupted)

        return result

    def largebin_index_32(self, sz: int) -> int:
        """Modeled on the GLIBC malloc largebin_index_32 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1414
        """
        return (
            56 + (sz >> 6)
            if (sz >> 6) <= 38
            else (
                91 + (sz >> 9)
                if (sz >> 9) <= 20
                else (
                    110 + (sz >> 12)
                    if (sz >> 12) <= 10
                    else (
                        119 + (sz >> 15)
                        if (sz >> 15) <= 4
                        else 124 + (sz >> 18)
                        if (sz >> 18) <= 2
                        else 126
                    )
                )
            )
        )

    def largebin_index_32_big(self, sz: int) -> int:
        """Modeled on the GLIBC malloc largebin_index_32_big macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1422
        """
        return (
            49 + (sz >> 6)
            if (sz >> 6) <= 45
            else (
                91 + (sz >> 9)
                if (sz >> 9) <= 20
                else (
                    110 + (sz >> 12)
                    if (sz >> 12) <= 10
                    else (
                        119 + (sz >> 15)
                        if (sz >> 15) <= 4
                        else 124 + (sz >> 18)
                        if (sz >> 18) <= 2
                        else 126
                    )
                )
            )
        )

    def largebin_index_64(self, sz: int) -> int:
        """Modeled on the GLIBC malloc largebin_index_64 macro.

        https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f7cd29bc2f93e1082ee77800bd64a4b2a2897055;hb=9ea3686266dca3f004ba874745a4087a89682617#l1433
        """
        return (
            48 + (sz >> 6)
            if (sz >> 6) <= 48
            else (
                91 + (sz >> 9)
                if (sz >> 9) <= 20
                else (
                    110 + (sz >> 12)
                    if (sz >> 12) <= 10
                    else (
                        119 + (sz >> 15)
                        if (sz >> 15) <= 4
                        else 124 + (sz >> 18)
                        if (sz >> 18) <= 2
                        else 126
                    )
                )
            )
        )

    def largebin_index(self, sz: int):
        """Pick the appropriate largebin_index_ function for this architecture."""
        if pwndbg.aglib.arch.ptrsize == 8:
            return self.largebin_index_64(sz)
        elif self.malloc_alignment == 16:
            return self.largebin_index_32_big(sz)
        else:
            return self.largebin_index_32(sz)

    def is_initialized(self):
        raise NotImplementedError()

    def is_statically_linked(self) -> bool:
        return not pwndbg.dbg.selected_inferior().is_dynamically_linked()

    def libc_has_debug_syms(self) -> bool:
        """
        The `struct malloc_chunk` comes from debugging symbols and it will not be there
        for statically linked binaries
        """
        return (
            pwndbg.aglib.typeinfo.load("struct malloc_chunk") is not None
            and pwndbg.aglib.symbol.lookup_symbol_addr("global_max_fast", prefer_static=True)
            is not None
        )


class DebugSymsHeap(GlibcMemoryAllocator[pwndbg.dbg_mod.Type, pwndbg.dbg_mod.Value]):
    def can_be_resolved(self) -> bool:
        if not self.libc_has_debug_syms():
            return False
        # Check if thread_arena is needed and available, but if the binary is not multithreaded, then we don't care
        # Note: it's possible that we unstripped the libc but still don't have libthread_db.so
        return (
            not self.multithreaded
            or pwndbg.aglib.symbol.lookup_symbol_addr("thread_arena", prefer_static=True)
            is not None
        )

    @property
    def main_arena(self) -> Arena | None:
        self._main_arena_addr = pwndbg.aglib.symbol.lookup_symbol_addr(
            "main_arena", prefer_static=True
        )
        if self._main_arena_addr is not None:
            self._main_arena = Arena(self._main_arena_addr)

        return self._main_arena

    def has_tcache(self) -> bool:
        return self.mp is not None and "tcache_bins" in self.mp.type.keys()

    @property
    def thread_arena(self) -> Arena | None:
        if self.multithreaded:
            thread_arena_addr = pwndbg.aglib.symbol.lookup_symbol_addr(
                "thread_arena", prefer_static=True
            )
            if thread_arena_addr:
                thread_arena_value = pwndbg.aglib.memory.pvoid(thread_arena_addr)
                # thread_arena might be NULL if the thread doesn't allocate arena yet
                if thread_arena_value:
                    return Arena(pwndbg.aglib.memory.pvoid(thread_arena_addr))
            return None
        else:
            return self.main_arena

    @property
    def thread_cache(self) -> pwndbg.dbg_mod.Value | None:
        """Locate a thread's tcache struct. If it doesn't have one, use the main
        thread's tcache.
        """
        if self.has_tcache():
            if self.multithreaded:
                tcache_addr = pwndbg.aglib.memory.pvoid(
                    pwndbg.aglib.symbol.lookup_symbol_addr("tcache", prefer_static=True)
                )
                if tcache_addr == 0:
                    # This thread doesn't have a tcache yet
                    return None
                tcache = tcache_addr
            else:
                tcache = self.main_arena.heaps[0].start + pwndbg.aglib.arch.ptrsize * 2

            try:
                self._thread_cache = pwndbg.aglib.memory.get_typed_pointer_value(
                    self.tcache_perthread_struct, tcache
                )
                self._thread_cache["entries"].fetch_lazy()
            except Exception:
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
    def mp(self) -> pwndbg.dbg_mod.Value | None:
        self._mp_addr = pwndbg.aglib.symbol.lookup_symbol_addr("mp_", prefer_static=True)
        if self._mp_addr is not None and self.malloc_par is not None:
            self._mp = pwndbg.aglib.memory.get_typed_pointer_value(self.malloc_par, self._mp_addr)

        return self._mp

    @property
    def global_max_fast(self) -> int | None:
        self._global_max_fast_addr = pwndbg.aglib.symbol.lookup_symbol_addr(
            "global_max_fast", prefer_static=True
        )
        if self._global_max_fast_addr is not None:
            self._global_max_fast = pwndbg.aglib.memory.u(self._global_max_fast_addr)

        return self._global_max_fast

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def heap_info(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("heap_info")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_chunk(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct malloc_chunk")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_state(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct malloc_state")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def tcache_perthread_struct(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct tcache_perthread_struct")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def tcache_entry(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct tcache_entry")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def mallinfo(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct mallinfo")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_par(self) -> pwndbg.dbg_mod.Type | None:
        return pwndbg.aglib.typeinfo.load("struct malloc_par")

    def get_heap(self, addr: int) -> pwndbg.dbg_mod.Value | None:
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        if self.heap_info is None:
            return None
        return pwndbg.aglib.memory.get_typed_pointer_value(self.heap_info, heap_for_ptr(addr))

    def get_tcache(
        self, tcache_addr: int | pwndbg.dbg_mod.Value | None = None
    ) -> pwndbg.dbg_mod.Value | None:
        if tcache_addr is None:
            return self.thread_cache

        return pwndbg.aglib.memory.get_typed_pointer_value(
            self.tcache_perthread_struct, tcache_addr
        )

    def get_sbrk_heap_region(self) -> pwndbg.lib.memory.Page | None:
        """Return a Page object representing the sbrk heap region.
        Ensure the region's start address is aligned to SIZE_SZ * 2,
        which compensates for the presence of GLIBC_TUNABLES.
        """
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        assert self.mp is not None
        sbrk_base = pwndbg.lib.memory.align_up(
            int(self.mp["sbrk_base"]), pwndbg.aglib.heap.current.size_sz * 2
        )

        sbrk_region = self.get_region(sbrk_base)
        if sbrk_region is None:
            return None
        sbrk_region.memsz = sbrk_region.end - sbrk_base
        sbrk_region.vaddr = sbrk_base

        return sbrk_region

    def is_initialized(self) -> bool:
        addr = pwndbg.aglib.symbol.lookup_symbol_addr("__libc_malloc_initialized")
        if addr is None:
            addr = pwndbg.aglib.symbol.lookup_symbol_addr("__malloc_initialized")
        assert addr is not None, "Could not find __libc_malloc_initialized or __malloc_initialized"
        return pwndbg.aglib.memory.s32(addr) > 0


class SymbolUnresolvableError(Exception):
    def __init__(self, symbol: str) -> None:
        super().__init__(f"`{symbol}` can not be resolved via heuristic")
        self.symbol = symbol


class HeuristicHeap(
    GlibcMemoryAllocator[
        typing.Type["pwndbg.aglib.heap.structs.CStruct2GDB"],
        "pwndbg.aglib.heap.structs.CStruct2GDB",
    ]
):
    def __init__(self) -> None:
        super().__init__()
        self._structs_module: types.ModuleType | None = None
        self._thread_arena_values: Dict[int, int] = {}
        self._thread_caches: Dict[int, Any] = {}

    @property
    def struct_module(self) -> types.ModuleType | None:
        if not self._structs_module and pwndbg.glibc.get_version():
            try:
                self._structs_module = importlib.reload(
                    importlib.import_module("pwndbg.aglib.heap.structs")
                )
            except Exception:
                pass
        return self._structs_module

    def can_be_resolved(self) -> bool:
        return self.struct_module is not None

    @property
    def main_arena(self) -> Arena | None:
        main_arena_via_config = int(str(pwndbg.config.main_arena), 0)
        main_arena_via_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
            "main_arena", prefer_static=True
        )
        if main_arena_via_config or main_arena_via_symbol:
            self._main_arena_addr = main_arena_via_config or main_arena_via_symbol

        if not self._main_arena_addr:
            if self.is_statically_linked():
                data_section = pwndbg.aglib.proc.dump_elf_data_section()
                data_section_address = pwndbg.aglib.proc.get_section_address_by_name(".data")
            else:
                data_section = pwndbg.glibc.dump_elf_data_section()
                data_section_address = pwndbg.glibc.get_section_address_by_name(".data")
            if data_section and data_section_address:
                data_section_offset, size, data_section_data = data_section
                # Try to find the default main_arena struct in the .data section
                # https://github.com/bminor/glibc/blob/glibc-2.37/malloc/malloc.c#L1902-L1907
                # static struct malloc_state main_arena =
                # {
                #   .mutex = _LIBC_LOCK_INITIALIZER,
                #   .next = &main_arena,
                #   .attached_threads = 1
                # };
                expected = self.malloc_state._c_struct()
                expected.attached_threads = 1
                next_field_offset = self.malloc_state.get_field_offset("next")
                malloc_state_size = self.malloc_state.sizeof

                # Since RELR relocations might also have .rela.dyn section, we check it first
                for section_name in (".relr.dyn", ".rela.dyn", ".rel.dyn"):
                    if self._main_arena_addr:
                        # If we have found the main_arena, we can stop searching
                        break

                    if self.is_statically_linked():
                        relocations = pwndbg.aglib.proc.dump_relocations_by_section_name(
                            section_name
                        )
                    else:
                        relocations = pwndbg.glibc.dump_relocations_by_section_name(section_name)
                    if not relocations:
                        continue

                    for relocation in relocations:
                        r_offset = relocation.entry.r_offset

                        # We only care about the relocation in .data section
                        if r_offset - next_field_offset < data_section_offset:
                            continue

                        if r_offset - next_field_offset >= data_section_offset + size:
                            break

                        # To find addend:
                        # .relr.dyn and .rel.dyn need to read the data from r_offset
                        # .rela.dyn has the addend in the entry
                        if section_name != ".rela.dyn":
                            addend = int.from_bytes(
                                data_section_data[
                                    r_offset - data_section_offset : r_offset
                                    - data_section_offset
                                    + pwndbg.aglib.arch.ptrsize
                                ],
                                pwndbg.aglib.arch.endian,
                            )
                        else:
                            addend = relocation.entry.r_addend

                        # If addend is the offset of main_arena, then r_offset should be the offset of main_arena.next
                        if r_offset - next_field_offset == addend:
                            # Check if we can construct the default main_arena struct we expect
                            tmp = data_section_data[
                                addend - data_section_offset : addend
                                - data_section_offset
                                + malloc_state_size
                            ]
                            # Note: Although RELA relocations have r_addend, some compiler will still put the addend in the location of r_offset, so we still need to check both cases
                            found = False
                            expected.next = addend
                            found |= bytes(expected) == tmp
                            if not found:
                                expected.next = 0
                                found |= bytes(expected) == tmp
                            if found:
                                # This might be a false positive, but it is very unlikely, so should be fine :)
                                self._main_arena_addr = (
                                    data_section_address + addend - data_section_offset
                                )
                                break

                # If we are still not able to find the main_arena, probably we are debugging a binary with statically linked libc and no PIE enabled
                if not self._main_arena_addr:
                    # Try to find the default main_arena struct in the .data section
                    for i in range(0, size - self.malloc_state.sizeof, pwndbg.aglib.arch.ptrsize):
                        expected.next = data_section_offset + i
                        if bytes(expected) == data_section_data[i : i + malloc_state_size]:
                            # This also might be a false positive, but it is very unlikely too, so should also be fine :)
                            self._main_arena_addr = data_section_address + i
                            break

        if pwndbg.aglib.memory.is_readable_address(self._main_arena_addr):
            self._main_arena = Arena(self._main_arena_addr)
            return self._main_arena

        raise SymbolUnresolvableError("main_arena")

    def has_tcache(self) -> bool:
        # TODO/FIXME: Can we determine the tcache_bins existence more reliable?

        # There is no debug symbols, we determine the tcache_bins existence by checking glibc version only
        return self.is_initialized() and pwndbg.glibc.get_version() >= (2, 26)

    def prompt_for_brute_force_thread_arena_permission(self) -> bool:
        """Check if the user wants to brute force the thread_arena's value."""
        print(
            message.notice("We cannot determine the %s\n" % message.hint("thread_arena"))
            + message.notice(
                "Will you want to brute force it in the memory to determine the address? (y/N)\n"
            )
            + message.warn(
                "Note: This might take a while and might not be reliable, so if you can determine it by yourself or you have modified any of the arena, please do not use this."
            )
        )
        return input().lower() == "y"

    def prompt_for_brute_force_thread_cache_permission(self) -> bool:
        """Check if the user wants to brute force the tcache's value."""
        print(
            message.notice("We cannot determine the %s\n" % message.hint("tcache"))
            + message.notice(
                "Will you want to brute force it in the memory to determine the address instead of assuming it's at the beginning of the current thread's heap? (y/N)\n"
            )
            + message.warn(
                "Note: This might take a while and might not be reliable, so if you can determine it by yourself or your current arena is corrupted or you have modified the chunk for the tcache, please do not use this."
            )
        )
        return input().lower() == "y"

    def prompt_for_tls_address(self) -> int:
        """Check if we can determine the TLS address and return it."""
        tls_address = pwndbg.aglib.tls.find_address_with_register()
        if not tls_address:
            print(
                message.warn("Cannot find TLS address via register. ")
                + message.notice(
                    "Will you want to call pthread_self() to find the address? (y/N)\n"
                )
                + message.warn("Note: Don't use this if pthread_self() is not available.")
            )
            if input().lower() == "y":
                tls_address = pwndbg.aglib.tls.find_address_with_pthread_self()
            if not tls_address:
                print(message.error("Cannot find TLS address via pthread_self()."))
        return tls_address

    def brute_force_tls_reference_in_got_section(
        self, tls_address: int, validator: Callable[[int], bool]
    ) -> Tuple[int, int] | None:
        """Brute force the TLS-reference in the .got section to that can pass the validator."""
        # Note: This highly depends on the correctness of the TLS address
        print(message.notice("Brute forcing the TLS-reference in the .got section..."))
        if self.is_statically_linked():
            got_address = pwndbg.aglib.proc.get_section_address_by_name(".got")
        else:
            got_address = pwndbg.glibc.get_section_address_by_name(".got")
        if not got_address:
            print(message.warn("Cannot find the address of the .got section."))
            return None
        s_int = (
            pwndbg.aglib.memory.s32 if pwndbg.aglib.arch.ptrsize == 4 else pwndbg.aglib.memory.s64
        )
        for addr in range(got_address, got_address + 0xF0, pwndbg.aglib.arch.ptrsize):
            if not pwndbg.aglib.memory.is_readable_address(addr):
                break
            offset = s_int(addr)
            if (
                offset
                and offset % pwndbg.aglib.arch.ptrsize == 0
                and pwndbg.aglib.memory.is_readable_address(offset + tls_address)
            ):
                guess = pwndbg.aglib.memory.pvoid(offset + tls_address)
                if validator(guess):
                    return guess, offset + tls_address
        return None

    def brute_force_thread_local_variable_near_tls_base(
        self, tls_address: int, validator: Callable[[int], bool]
    ) -> Tuple[int, int] | None:
        """Brute force the thread-local variable near the TLS base address that can pass the validator."""
        print(
            message.notice(
                "Brute forcing all the possible thread-local variables near the TLS base address..."
            )
        )
        for search_range in (
            range(tls_address, tls_address - 0x500, -pwndbg.aglib.arch.ptrsize),
            range(tls_address, tls_address + 0x500, pwndbg.aglib.arch.ptrsize),
        ):
            reading = False
            for addr in search_range:
                if pwndbg.aglib.memory.is_readable_address(addr):
                    reading = True
                    guess = pwndbg.aglib.memory.pvoid(addr)
                    if validator(guess):
                        return guess, addr
                elif reading:
                    # Don't need to try now, we only read consecutive memory
                    break
        return None

    @property
    def thread_arena(self) -> Arena | None:
        thread_arena_via_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
            "thread_arena", prefer_static=True
        )
        if thread_arena_via_symbol:
            thread_arena_value = pwndbg.aglib.memory.pvoid(thread_arena_via_symbol)
            return Arena(thread_arena_value) if thread_arena_value else None
        thread_arena_via_config = int(str(pwndbg.config.thread_arena), 0)
        if thread_arena_via_config:
            return Arena(thread_arena_via_config)

        # return the value of the thread_arena if we have it cached
        thread_arena_value = self._thread_arena_values.get(pwndbg.dbg.selected_thread().index())
        if thread_arena_value:
            return Arena(thread_arena_value)

        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        if (
            self.main_arena.address != pwndbg.aglib.heap.current.main_arena.next
            or self.multithreaded
        ):
            if pwndbg.aglib.arch.name not in ("i386", "x86-64", "arm", "aarch64"):
                # TODO: Support other architectures
                raise SymbolUnresolvableError("thread_arena")
            if self.prompt_for_brute_force_thread_arena_permission():
                tls_address = self.prompt_for_tls_address()
                if not tls_address:
                    raise SymbolUnresolvableError("thread_arena")
                print(message.notice("Fetching all the arena addresses..."))
                candidates = [a.address for a in self.arenas]

                def validator(guess: int) -> bool:
                    return guess in candidates

                found = self.brute_force_tls_reference_in_got_section(
                    tls_address, validator
                ) or self.brute_force_thread_local_variable_near_tls_base(tls_address, validator)
                if found:
                    value, address = found
                    print(
                        message.notice(
                            f"Found matching arena address {message.hint(hex(value))} at {message.hint(hex(address))}\n"
                        )
                    )
                    arena = Arena(value)
                    self._thread_arena_values[pwndbg.dbg.selected_thread().index()] = value
                    return arena

                print(
                    message.notice(
                        f"Cannot find {message.hint('thread_arena')}, the arena might be not allocated yet.\n"
                    )
                )
                return None
            raise SymbolUnresolvableError("thread_arena")
        else:  # noqa: RET506
            self._thread_arena_values[pwndbg.dbg.selected_thread().index()] = (
                self.main_arena.address
            )
            return self.main_arena

    @property
    def thread_cache(self) -> "pwndbg.aglib.heap.structs.TcachePerthreadStruct" | None:
        """Locate a thread's tcache struct. We try to find its address in Thread Local Storage (TLS) first,
        and if that fails, we guess it's at the first chunk of the heap.
        """
        if not self.has_tcache():
            print(message.warn("This version of GLIBC was not compiled with tcache support."))
            return None
        tps = self.tcache_perthread_struct
        thread_cache_via_config = int(str(pwndbg.config.tcache), 0)
        thread_cache_via_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
            "tcache", prefer_static=True
        )
        if thread_cache_via_config:
            self._thread_cache = tps(thread_cache_via_config)
            return self._thread_cache
        elif thread_cache_via_symbol:
            thread_cache_struct_addr = pwndbg.aglib.memory.pvoid(thread_cache_via_symbol)
            if thread_cache_struct_addr:
                self._thread_cache = tps(int(thread_cache_struct_addr))
                return self._thread_cache

        # return the value of tcache if we have it cached
        if self._thread_caches.get(pwndbg.dbg.selected_thread().index()):
            return self._thread_caches[pwndbg.dbg.selected_thread().index()]

        arena = self.thread_arena
        if not arena:
            # arena doesn't be allocated yet, so there's no tcache
            return None

        if self.main_arena.next != self.main_arena.address or self.multithreaded:
            if self.prompt_for_brute_force_thread_cache_permission():
                tls_address = self.prompt_for_tls_address()
                if tls_address:
                    chunk_header_size = pwndbg.aglib.arch.ptrsize * 2
                    tcache_perthread_struct_size = self.tcache_perthread_struct.sizeof
                    lb, ub = arena.active_heap.start, arena.active_heap.end

                    def validator(guess: int) -> bool:
                        if guess < lb or guess >= ub:
                            return False
                        if not pwndbg.aglib.memory.is_readable_address(
                            guess - chunk_header_size
                        ) or not pwndbg.aglib.memory.is_readable_address(
                            guess + tcache_perthread_struct_size
                        ):
                            return False
                        chunk = Chunk(guess - chunk_header_size)
                        return chunk.real_size - chunk_header_size == tcache_perthread_struct_size

                    found = self.brute_force_tls_reference_in_got_section(
                        tls_address, validator
                    ) or self.brute_force_thread_local_variable_near_tls_base(
                        tls_address, validator
                    )
                    if found:
                        value, address = found
                        print(
                            message.notice(
                                f"Found possible tcache at {message.hint(hex(address))} with value: {message.hint(hex(value))}\n"
                            )
                        )
                        self._thread_cache = tps(value)
                        self._thread_caches[pwndbg.dbg.selected_thread().index()] = (
                            self._thread_cache
                        )
                        return self._thread_cache

            print(
                message.warn(
                    "Cannot find tcache, we assume it's at the beginning of the heap.\n"
                    "If you think this is wrong, please manually set it with `set tcache <address>`.\n"
                )
            )

        # TODO: The result might be wrong if the arena is being shared by multiple thread
        self._thread_cache = tps(arena.heaps[0].start + pwndbg.aglib.arch.ptrsize * 2)
        self._thread_caches[pwndbg.dbg.selected_thread().index()] = self._thread_cache

        return self._thread_cache

    @property
    def mp(self) -> "pwndbg.aglib.heap.structs.CStruct2GDB":
        mp_via_config = int(str(pwndbg.config.mp), 0)
        mp_via_symbol = pwndbg.aglib.symbol.lookup_symbol_addr("mp_", prefer_static=True)
        if mp_via_config or mp_via_symbol:
            self._mp_addr = mp_via_symbol

        if not self._mp_addr:
            if self.is_statically_linked():
                section = pwndbg.aglib.proc.dump_elf_data_section()
                section_address = pwndbg.aglib.proc.get_section_address_by_name(".data")
            else:
                section = pwndbg.glibc.dump_elf_data_section()
                section_address = pwndbg.glibc.get_section_address_by_name(".data")
            if section and section_address:
                _, _, data = section

                # try to find the default mp_ struct in the .data section
                found = data.find(bytes(self.struct_module.DEFAULT_MP_))
                if found != -1:
                    self._mp_addr = section_address + found

        if pwndbg.aglib.memory.is_readable_address(self._mp_addr):
            mps = self.malloc_par
            self._mp = mps(self._mp_addr)
            return self._mp

        raise SymbolUnresolvableError("mp_")

    @property
    def global_max_fast(self) -> int:
        global_max_fast_via_config = int(str(pwndbg.config.global_max_fast), 0)
        global_max_fast_via_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
            "global_max_fast", prefer_static=True
        )

        if global_max_fast_via_config or global_max_fast_via_symbol:
            self._global_max_fast_addr = global_max_fast_via_config or global_max_fast_via_symbol
            self._global_max_fast = pwndbg.aglib.memory.u(self._global_max_fast_addr)
            return self._global_max_fast

        # https://elixir.bootlin.com/glibc/glibc-2.37/source/malloc/malloc.c#L836
        # https://elixir.bootlin.com/glibc/glibc-2.37/source/malloc/malloc.c#L1773
        # https://elixir.bootlin.com/glibc/glibc-2.37/source/malloc/malloc.c#L1953
        default = (64 * self.size_sz // 4 + self.size_sz) & ~self.malloc_align_mask
        print(
            message.warn(
                "global_max_fast symbol not found, using the default value: 0x%x" % default
            )
        )
        print(
            message.warn(
                "Use `set global-max-fast <address>` to set the address of global_max_fast manually if needed."
            )
        )
        return default

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def heap_info(self) -> Type["pwndbg.aglib.heap.structs.HeapInfo"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.HeapInfo

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_chunk(self) -> Type["pwndbg.aglib.heap.structs.MallocChunk"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.MallocChunk

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_state(self) -> Type["pwndbg.aglib.heap.structs.MallocState"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.MallocState

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def tcache_perthread_struct(
        self,
    ) -> Type["pwndbg.aglib.heap.structs.TcachePerthreadStruct"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.TcachePerthreadStruct

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def tcache_entry(self) -> Type["pwndbg.aglib.heap.structs.TcacheEntry"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.TcacheEntry

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def mallinfo(self) -> Type["pwndbg.aglib.heap.structs.CStruct2GDB"] | None:
        # TODO/FIXME: Currently, we don't need to create a new class for `struct mallinfo` because we never use it.
        raise NotImplementedError("`struct mallinfo` is not implemented yet.")

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def malloc_par(self) -> Type["pwndbg.aglib.heap.structs.MallocPar"] | None:
        if not self.struct_module:
            return None
        return self.struct_module.MallocPar

    def get_heap(self, addr: int) -> "pwndbg.aglib.heap.structs.HeapInfo" | None:
        """Find & read the heap_info struct belonging to the chunk at 'addr'."""
        hi = self.heap_info
        return hi(heap_for_ptr(addr))

    def get_tcache(
        self, tcache_addr: int | None = None
    ) -> "pwndbg.aglib.heap.structs.TcachePerthreadStruct" | None:
        if tcache_addr is None:
            return self.thread_cache

        tps = self.tcache_perthread_struct
        return tps(tcache_addr)

    def get_sbrk_heap_region(self) -> pwndbg.lib.memory.Page:
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
                assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
                sbrk_base = pwndbg.lib.memory.align_up(
                    int(self.mp["sbrk_base"]), pwndbg.aglib.heap.current.size_sz * 2
                )

                sbrk_region = self.get_region(sbrk_base)
                if sbrk_region is None:
                    raise ValueError("mp_.sbrk_base is unmapped or points to unmapped memory.")
                sbrk_region.memsz = sbrk_region.end - sbrk_base
                sbrk_region.vaddr = sbrk_base

                return sbrk_region
            else:
                raise ValueError("mp_.sbrk_base is unmapped or points to unmapped memory.")
        else:
            raise SymbolUnresolvableError("mp_")

    def is_initialized(self) -> bool:
        # TODO/FIXME: If main_arena['top'] is been modified to 0, this will not work.
        # try to use vmmap or main_arena.top to find the heap
        return any("[heap]" == x.objfile for x in pwndbg.aglib.vmmap.get()) or (
            self.can_be_resolved() and self.main_arena.top != 0
        )
