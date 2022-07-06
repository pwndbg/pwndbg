import gdb

import pwndbg.arch
import pwndbg.heap
import pwndbg.typeinfo
import pwndbg.memory
import pwndbg.glibc
import ctypes

NBINS = 128
BINMAPSIZE = 4
TCACHE_MAX_BINS = 64

if pwndbg.arch.ptrsize == 4:
    NFASTBINS = 11
    PTR = ctypes.c_uint32
    SIZE_T = ctypes.c_uint32
else:
    NFASTBINS = 10
    PTR = ctypes.c_uint64
    SIZE_T = ctypes.c_uint64

class CStruct2GDB:
    def __int__(self) -> int:
        return self.address
    
    def __getitem__(self, key: str) -> gdb.Value:
        return getattr(self, key)
    
    def __eq__(self, other) -> bool:
        return self.address == int(other)
    
    def __str__(self) -> str:
        output = "{\n"
        for f in self._c_struct._fields_:
            output += "  %s = %s,\n" % (f[0], getattr(self, f[0]))
        output += "}"
        return output

    @property
    def type(self):
        """
        Returns self to make it compatible with the `gdb.Value` interface.
        """
        return self
    
    def field_address(self, field: str) -> int:
        return self.address + getattr(self._c_struct, field).offset

    def items(self) -> tuple:
        return tuple((field[0], getattr(self, field[0])) for field in self._c_struct._fields_)

class c_malloc_state_2_26(ctypes.LittleEndianStructure):
    _fields_ = [
        ('mutex', ctypes.c_int32),
        ('flags', ctypes.c_int32),
        ('fastbinsY', PTR * NFASTBINS),
        ('top', PTR),
        ('last_remainder', PTR),
        ('bins', PTR * (NBINS * 2 - 2)),
        ('binmap', ctypes.c_int32 * BINMAPSIZE),
        ('next', PTR),
        ('next_free', PTR),
        ('attached_threads', SIZE_T),
        ('system_mem', SIZE_T),
        ('max_system_mem', SIZE_T),
    ]

class c_malloc_state_2_27(ctypes.LittleEndianStructure):
    _fields_ = [
        ('mutex', ctypes.c_int32),
        ('flags', ctypes.c_int32),
        ('have_fastchunks', ctypes.c_int32),
        ('fastbinsY', PTR * NFASTBINS),
        ('top', PTR),
        ('last_remainder', PTR),
        ('bins', PTR * (NBINS * 2 - 2)),
        ('binmap', ctypes.c_int32 * BINMAPSIZE),
        ('next', PTR),
        ('next_free', PTR),
        ('attached_threads', SIZE_T),
        ('system_mem', SIZE_T),
        ('max_system_mem', SIZE_T),
    ]

class MallocState(CStruct2GDB):
    """
    This class represents malloc_state struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L1831

    Note: glibc < 2.27 does not have `have_fastchunks` field.

    struct malloc_state
    {
        /* Serialize access.  */
        __libc_lock_define (, mutex);

        /* Flags (formerly in max_fast).  */
        int flags;

        /* Set if the fastbin chunks contain recently inserted free blocks.  */
        /* Note this is a bool but not all targets support atomics on booleans.  */
        int have_fastchunks;

        /* Fastbins */
        mfastbinptr fastbinsY[NFASTBINS];

        /* Base of the topmost chunk -- not otherwise kept in a bin */
        mchunkptr top;

        /* The remainder from the most recent split of a small request */
        mchunkptr last_remainder;

        /* Normal bins packed as described above */
        mchunkptr bins[NBINS * 2 - 2];

        /* Bitmap of bins */
        unsigned int binmap[BINMAPSIZE];

        /* Linked list */
        struct malloc_state *next;

        /* Linked list for free arenas.  Access to this field is serialized
            by free_list_lock in arena.c.  */
        struct malloc_state *next_free;

        /* Number of threads attached to this arena.  0 if the arena is on
            the free list.  Access to this field is serialized by
            free_list_lock in arena.c.  */
        INTERNAL_SIZE_T attached_threads;

        /* Memory allocated from the system in this arena.  */
        INTERNAL_SIZE_T system_mem;
        INTERNAL_SIZE_T max_system_mem;
    };
    """
    if pwndbg.glibc.get_version() >= (2, 27):
        _c_struct = c_malloc_state_2_27
        sizeof = ctypes.sizeof(_c_struct)
    else:
        _c_struct = c_malloc_state_2_26
        sizeof = ctypes.sizeof(_c_struct)
    
    def __init__(self, address: int) -> None:
        self.address = address
    
    @property
    def mutex(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.mutex.offset)
    
    @property
    def flags(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.flags.offset)

    @property
    def have_fastchunks(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.have_fastchunks.offset)

    @property
    def fastbinsY(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid.array(NFASTBINS - 1), self.address + self._c_struct.fastbinsY.offset)
    
    @property
    def top(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.top.offset)
    
    @property
    def last_remainder(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.last_remainder.offset)
    
    @property
    def bins(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid.array((NBINS * 2 - 2) - 1), self.address + self._c_struct.bins.offset)
    
    @property
    def binmap(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32.array(BINMAPSIZE - 1), self.address + self._c_struct.binmap.offset)
    
    @property
    def next(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.next.offset)
    
    @property
    def next_free(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.next_free.offset)
    
    @property
    def attached_threads(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.attached_threads.offset)
    
    @property
    def system_mem(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.system_mem.offset)
    
    @property
    def max_system_mem(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.max_system_mem.offset)

    @staticmethod
    def keys() -> tuple:
        """
        Use @staticmethod to make it compatible with the `gdb.Type` insterface.
        """
        if pwndbg.glibc.get_version() >= (2, 27):
            return tuple(field[0] for field in c_malloc_state_2_27._fields_)
        else:
            return tuple(field[0] for field in c_malloc_state_2_26._fields_)

class c_heap_info(ctypes.LittleEndianStructure):
    _fields_ = [
        ('ar_ptr', PTR),
        ('prev', PTR),
        ('next', PTR),
        ('size', SIZE_T),
        ('pad', ctypes.c_uint8 * (8 if pwndbg.arch.ptrsize == 4 else 0)),
    ]

class HeapInfo(CStruct2GDB):
    """
    This class represents _heap_info struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/arena.c#L53

    typedef struct _heap_info
    {
        mstate ar_ptr; /* Arena for this heap. */
        struct _heap_info *prev; /* Previous heap. */
        size_t size;   /* Current size in bytes. */
        size_t mprotect_size; /* Size in bytes that has been mprotected
                                PROT_READ|PROT_WRITE.  */
        /* Make sure the following data is properly aligned, particularly
            that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
            MALLOC_ALIGNMENT. */
        char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
    } heap_info;
    """
    _c_struct = c_heap_info
    sizeof = ctypes.sizeof(_c_struct)

    def __init__(self, address: int) -> None:
        self.address = address
    
    @property
    def ar_ptr(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.ar_ptr.offset)
    
    @property
    def prev(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.prev.offset)
    
    @property
    def size(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.size.offset)
    
    @property
    def mprotect_size(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.mprotect_size.offset)

    @property
    def pad(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.char.array((8 if pwndbg.arch.ptrsize == 4 else 0) - 1), self.address + self._c_struct.pad.offset)
    
    @staticmethod
    def keys() -> tuple:
        return tuple(field[0] for field in c_heap_info._fields_)

class c_malloc_chunk(ctypes.LittleEndianStructure):
    _fields_ = [
        ('prev_size', SIZE_T),
        ('size', SIZE_T),
        ('fd', PTR),
        ('bk', PTR),
        ('fd_nextsize', PTR),
        ('bk_nextsize', PTR),
    ]

class MallocChunk(CStruct2GDB):
    """
    This class represents malloc_chunk struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L1154
    
    struct malloc_chunk {

        INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
        INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

        struct malloc_chunk* fd;         /* double links -- used only if free. */
        struct malloc_chunk* bk;

        /* Only used for large blocks: pointer to next larger size.  */
        struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
        struct malloc_chunk* bk_nextsize;
    };
    """
    _c_struct = c_malloc_chunk
    sizeof = ctypes.sizeof(_c_struct)

    def __init__(self, address: int) -> None:
        self.address = address
    
    @property
    def prev_size(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.prev_size.offset)
    
    @property
    def size(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.size.offset)
    
    @property
    def fd(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.fd.offset)
    
    @property
    def bk(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.bk.offset)
    
    @property
    def fd_nextsize(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.fd_nextsize.offset)
    
    @property
    def bk_nextsize(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.bk_nextsize.offset)
    
    @staticmethod
    def keys() -> tuple:
        return tuple(field[0] for field in c_malloc_chunk._fields_)

class c_tcache_perthread_struct(ctypes.LittleEndianStructure):
    _fields_ = [
        ('counts', ctypes.c_uint16 * TCACHE_MAX_BINS),
        ('entries', PTR * TCACHE_MAX_BINS)
    ]

class TcachePerthreadStruct(CStruct2GDB):
    """
    This class represents the tcache_perthread_struct struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L3025

    typedef struct tcache_perthread_struct
    {
        uint16_t counts[TCACHE_MAX_BINS];
        tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    """
    _c_struct = c_tcache_perthread_struct
    sizeof = ctypes.sizeof(_c_struct)

    def __init__(self, address: int) -> None:
        self.address = address

    @property
    def counts(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.uint16.array(TCACHE_MAX_BINS - 1), self.address + self._c_struct.counts.offset)
    
    @property
    def entries(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid.array(TCACHE_MAX_BINS - 1), self.address + self._c_struct.entries.offset)

    @staticmethod
    def keys() -> tuple:
        return tuple(field[0] for field in c_tcache_perthread_struct._fields_)

class c_tcache_entry_2_28(ctypes.LittleEndianStructure):
    _fields_ = [
        ('next', PTR)
    ]

class c_tcache_entry_2_29(ctypes.LittleEndianStructure):
    _fields_ = [
        ('next', PTR),
        ('key', PTR)
    ]

class TcacheEntry:
    """
    This class represents the tcache_entry struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L3013

    Note: glibc < 2.29 does not have `key` field.

    typedef struct tcache_entry
    {
        struct tcache_entry *next;
        /* This field exists to detect double frees.  */
        uintptr_t key;
    } tcache_entry;
    """
    if pwndbg.glibc.get_version() >= (2, 29):
        _c_struct = c_tcache_entry_2_29
        sizeof = ctypes.sizeof(_c_struct)
    else:
        _c_struct = c_tcache_entry_2_28
        sizeof = ctypes.sizeof(_c_struct)

    def __init__(self, address: int) -> None:
        self.address = address
    
    @property
    def next(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.next.offset)
    
    @property
    def key(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.key.offset)
    
    @staticmethod
    def keys() -> tuple:
        if pwndbg.glibc.get_version() >= (2, 29):
            return tuple(field[0] for field in c_tcache_entry_2_29._fields_)
        else:
            return tuple(field[0] for field in c_tcache_entry_2_28._fields_)

class c_malloc_par_2_25(ctypes.LittleEndianStructure):
    _fields_ = [
        ('trim_threshold', SIZE_T),
        ('top_pad', SIZE_T),
        ('mmap_threshold', SIZE_T),
        ('arena_test', SIZE_T),
        ('arena_max', SIZE_T),
        ('n_mmaps', ctypes.c_int32),
        ('n_mmaps_max', ctypes.c_int32),
        ('max_n_mmaps', ctypes.c_int32),
        ('no_dyn_threshold', ctypes.c_int32),
        ('mmaped_mem', SIZE_T),
        ('max_mmaped_mem', SIZE_T),
        ('sbrk_base', PTR)
    ]

class c_malloc_par_2_26(ctypes.LittleEndianStructure):
    _fields_ = [
        ('trim_threshold', SIZE_T),
        ('top_pad', SIZE_T),
        ('mmap_threshold', SIZE_T),
        ('arena_test', SIZE_T),
        ('arena_max', SIZE_T),
        ('n_mmaps', ctypes.c_int32),
        ('n_mmaps_max', ctypes.c_int32),
        ('max_n_mmaps', ctypes.c_int32),
        ('no_dyn_threshold', ctypes.c_int32),
        ('mmapped_mem', SIZE_T),
        ('max_mmapped_mem', SIZE_T),
        ('sbrk_base', PTR),
        ('tcache_bins', SIZE_T),
        ('tcache_max_bytes', SIZE_T),
        ('tcache_count', ctypes.c_int32),
        ('tcache_unsorted_limit', SIZE_T)
    ]

class MallocPar(CStruct2GDB):
    """
    This class represents the malloc_par struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L1875

    struct malloc_par
    {
        /* Tunable parameters */
        unsigned long trim_threshold;
        INTERNAL_SIZE_T top_pad;
        INTERNAL_SIZE_T mmap_threshold;
        INTERNAL_SIZE_T arena_test;
        INTERNAL_SIZE_T arena_max;

        /* Memory map support */
        int n_mmaps;
        int n_mmaps_max;
        int max_n_mmaps;
        /* the mmap_threshold is dynamic, until the user sets
            it manually, at which point we need to disable any
            dynamic behavior. */
        int no_dyn_threshold;

        /* Statistics */
        INTERNAL_SIZE_T mmapped_mem;
        INTERNAL_SIZE_T max_mmapped_mem;

        /* First address handed out by MORECORE/sbrk.  */
        char *sbrk_base;

        #if USE_TCACHE
        /* Maximum number of buckets to use.  */
        size_t tcache_bins;
        size_t tcache_max_bytes;
        /* Maximum number of chunks in each bucket.  */
        size_t tcache_count;
        /* Maximum number of chunks to remove from the unsorted list, which
            aren't used to prefill the cache.  */
        size_t tcache_unsorted_limit;
        #endif
    };
    """
    if pwndbg.glibc.get_version() >= (2, 26):
        _c_struct = c_malloc_par_2_26
        sizeof = ctypes.sizeof(_c_struct)
    else:
        _c_struct = c_malloc_par_2_25
        sizeof = ctypes.sizeof(_c_struct)

    def __init__(self, address: int) -> None:
        self.address = address
    
    @property
    def trim_threshold(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.ulong, self.address + self._c_struct.trim_threshold.offset)
    
    @property
    def top_pad(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.top_pad.offset)
    
    @property
    def mmap_threshold(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.mmap_threshold.offset)
    
    @property
    def arena_test(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.arena_test.offset)
    
    @property
    def arena_max(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.arena_max.offset)
    
    @property
    def n_mmaps(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.n_mmaps.offset)
    
    @property
    def n_mmaps_max(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.n_mmaps_max.offset)
    
    @property
    def max_n_mmaps(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.max_n_mmaps.offset)
    
    @property
    def no_dyn_threshold(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.int32, self.address + self._c_struct.no_dyn_threshold.offset)
    
    @property
    def mmapped_mem(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.mmapped_mem.offset)
    
    @property
    def max_mmapped_mem(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.max_mmapped_mem.offset)
    
    @property
    def sbrk_base(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.pvoid, self.address + self._c_struct.sbrk_base.offset)
    
    @property
    def tcache_bins(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.tcache_bins.offset)
    
    @property
    def tcache_max_bytes(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.tcache_max_bytes.offset)
    
    @property
    def tcache_count(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.tcache_count.offset)
    
    @property
    def tcache_unsorted_limit(self) -> gdb.Value:
        return pwndbg.memory.poi(pwndbg.typeinfo.size_t, self.address + self._c_struct.tcache_unsorted_limit.offset)

    @staticmethod
    def keys() -> tuple:
        if pwndbg.glibc.get_version() >= (2, 26):
            return tuple(field[0] for field in c_malloc_par_2_26._fields_)
        else:
            return tuple(field[0] for field in c_malloc_par_2_25._fields_)
