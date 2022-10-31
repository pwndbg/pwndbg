import ctypes

import gdb

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo
import pwndbg.glibc


def request2size(req):
    if req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE:
        return MINSIZE
    return (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK


def fastbin_index(size):
    if pwndbg.gdblib.arch.ptrsize == 8:
        return (size >> 4) - 2
    else:
        return (size >> 3) - 2


SIZE_SZ = pwndbg.gdblib.arch.ptrsize
MINSIZE = pwndbg.gdblib.arch.ptrsize * 4
# i386 will override it to 16.
# See https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/i386/malloc-alignment.h#L22
MALLOC_ALIGN = (
    16
    if pwndbg.gdblib.arch.current == "i386" and pwndbg.glibc.get_version() >= (2, 26)
    else pwndbg.gdblib.arch.ptrsize * 2
)
MALLOC_ALIGN_MASK = MALLOC_ALIGN - 1
MAX_FAST_SIZE = 80 * SIZE_SZ // 4
NBINS = 128
BINMAPSIZE = 4
TCACHE_MAX_BINS = 64
NFASTBINS = fastbin_index(request2size(MAX_FAST_SIZE)) + 1

if pwndbg.gdblib.arch.ptrsize == 4:
    PTR = ctypes.c_uint32
    SIZE_T = ctypes.c_uint32
else:
    PTR = ctypes.c_uint64
    SIZE_T = ctypes.c_uint64


class c_pvoid(PTR):
    """
    Represents a pointer.
    """


class c_size_t(SIZE_T):
    """
    Represents a size_t.
    """


C2GDB_MAPPING = {
    ctypes.c_char: pwndbg.gdblib.typeinfo.char,
    ctypes.c_int8: pwndbg.gdblib.typeinfo.int8,
    ctypes.c_int16: pwndbg.gdblib.typeinfo.int16,
    ctypes.c_int32: pwndbg.gdblib.typeinfo.int32,
    ctypes.c_int64: pwndbg.gdblib.typeinfo.int64,
    ctypes.c_uint8: pwndbg.gdblib.typeinfo.uint8,
    ctypes.c_uint16: pwndbg.gdblib.typeinfo.uint16,
    ctypes.c_uint32: pwndbg.gdblib.typeinfo.uint32,
    ctypes.c_uint64: pwndbg.gdblib.typeinfo.uint64,
    c_pvoid: pwndbg.gdblib.typeinfo.pvoid,
    c_size_t: pwndbg.gdblib.typeinfo.size_t,
}


class FakeGDBField:
    """
    Fake gdb.Field for compatibility
    """

    def __init__(
        self,
        bitpos,
        name,
        type,
        parent_type,
        enumval=None,
        artificial=False,
        is_base_class=False,
        bitsize=0,
    ):
        # Note: pwndbg only uses `name` currently
        self.bitpos = bitpos
        self.name = name
        self.type = type
        self.parent_type = parent_type
        if enumval:
            self.enumval = enumval
        self.artificial = artificial
        self.is_base_class = is_base_class
        self.bitsize = bitsize


class CStruct2GDB:
    code = gdb.TYPE_CODE_STRUCT
    _c_struct = None

    def __init__(self, address: int) -> None:
        self.address = address

    def __int__(self) -> int:
        """
        Returns the address of the C struct.
        """
        return self.address

    def __getitem__(self, key: str) -> gdb.Value:
        """
        Returns the value of the specified field as a `gdb.Value`.
        """
        return self.read_field(key)

    def __getattr__(self, key: str) -> gdb.Value:
        """
        Returns the value of the specified field as a `gdb.Value`.
        """
        return self.read_field(key)

    def __eq__(self, other) -> bool:
        return self.address == int(other)

    def __str__(self) -> str:
        """
        Returns a string representation of the C struct like `gdb.Value` does.
        """
        output = "{\n"
        for f in self._c_struct._fields_:
            output += "  %s = %s,\n" % (f[0], self.read_field(f[0]))
        output += "}"
        return output

    def read_field(self, field: str) -> gdb.Value:
        """
        Returns the value of the specified field as a `gdb.Value`.
        """
        field_address = self.get_field_address(field)
        field_type = next((f for f in self._c_struct._fields_ if f[0] == field))[1]
        if hasattr(field_type, "_length_"):  # f is a ctypes Array
            t = C2GDB_MAPPING[field_type._type_]
            return pwndbg.gdblib.memory.poi(t.array(field_type._length_ - 1), field_address)
        return pwndbg.gdblib.memory.poi(C2GDB_MAPPING[field_type], field_address)

    @property
    def type(self):
        """
        Returns type(self) to make it compatible with the `gdb.Value` interface.
        """
        return type(self)

    @classmethod
    def unqualified(cls):
        """
        Returns cls to make it compatible with the `gdb.types.has_field()` interface.
        """
        return cls

    @classmethod
    def fields(cls):
        """
        Return fields of the struct to make it compatible with the `gdb.Type` interface.
        """
        fake_gdb_fields = []
        for f in cls._c_struct._fields_:
            field_name = f[0]
            field_type = f[1]
            bitpos = getattr(cls._c_struct, field_name).offset * 8
            if hasattr(field_type, "_length_"):  # f is a ctypes Array
                t = C2GDB_MAPPING[field_type._type_]
                _type = t.array(field_type._length_ - 1)
            else:
                _type = C2GDB_MAPPING[field_type]
            fake_gdb_fields.append(FakeGDBField(bitpos, field_name, _type, cls))
        return fake_gdb_fields

    @classmethod
    def keys(cls) -> list:
        """
        Return a list of the names of the fields in the struct to make it compatible with the `gdb.Type` interface.
        """
        return [f[0] for f in cls._c_struct._fields_]

    def get_field_address(self, field: str) -> int:
        """
        Returns the address of the specified field.
        """
        return self.address + getattr(self._c_struct, field).offset

    def items(self) -> tuple:
        """
        Returns a tuple of (field name, field value) pairs.
        """
        return tuple((field[0], getattr(self, field[0])) for field in self._c_struct._fields_)


class c_malloc_state_2_26(ctypes.LittleEndianStructure):
    """
    This class represents malloc_state struct for GLIBC < 2.27 as a ctypes struct.

    https://github.com/bminor/glibc/blob/1c9a5c270d8b66f30dcfaf1cb2d6cf39d3e18369/malloc/malloc.c#L1678-L1716

    struct malloc_state
    {
        /* Serialize access.  */
        __libc_lock_define (, mutex);

        /* Flags (formerly in max_fast).  */
        int flags;

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

    _fields_ = [
        ("mutex", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("fastbinsY", c_pvoid * NFASTBINS),
        ("top", c_pvoid),
        ("last_remainder", c_pvoid),
        ("bins", c_pvoid * (NBINS * 2 - 2)),
        ("binmap", ctypes.c_int32 * BINMAPSIZE),
        ("next", c_pvoid),
        ("next_free", c_pvoid),
        ("attached_threads", c_size_t),
        ("system_mem", c_size_t),
        ("max_system_mem", c_size_t),
    ]


class c_malloc_state_2_27(ctypes.LittleEndianStructure):
    """
    This class represents malloc_state struct for GLIBC >= 2.27 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L1831


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

    _fields_ = [
        ("mutex", ctypes.c_int32),
        ("flags", ctypes.c_int32),
        ("have_fastchunks", ctypes.c_int32),
        ("fastbinsY", c_pvoid * NFASTBINS),
        ("top", c_pvoid),
        ("last_remainder", c_pvoid),
        ("bins", c_pvoid * (NBINS * 2 - 2)),
        ("binmap", ctypes.c_int32 * BINMAPSIZE),
        ("next", c_pvoid),
        ("next_free", c_pvoid),
        ("attached_threads", c_size_t),
        ("system_mem", c_size_t),
        ("max_system_mem", c_size_t),
    ]


class MallocState(CStruct2GDB):
    """
    This class represents malloc_state struct with interface compatible with `gdb.Value`.
    """

    if pwndbg.glibc.get_version() >= (2, 27):
        _c_struct = c_malloc_state_2_27
    else:
        _c_struct = c_malloc_state_2_26
    sizeof = ctypes.sizeof(_c_struct)


class c_heap_info(ctypes.LittleEndianStructure):
    """
    This class represents heap_info struct as a ctypes struct.

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

    _fields_ = [
        ("ar_ptr", c_pvoid),
        ("prev", c_pvoid),
        ("size", c_size_t),
        ("mprotect_size", c_size_t),
        ("pad", ctypes.c_uint8 * (-6 * SIZE_SZ & MALLOC_ALIGN_MASK)),
    ]


class HeapInfo(CStruct2GDB):
    """
    This class represents heap_info struct with interface compatible with `gdb.Value`.
    """

    _c_struct = c_heap_info
    sizeof = ctypes.sizeof(_c_struct)


class c_malloc_chunk(ctypes.LittleEndianStructure):
    """
    This class represents malloc_chunk struct as a ctypes struct.

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

    _fields_ = [
        ("prev_size", c_size_t),
        ("size", c_size_t),
        ("fd", c_pvoid),
        ("bk", c_pvoid),
        ("fd_nextsize", c_pvoid),
        ("bk_nextsize", c_pvoid),
    ]


class MallocChunk(CStruct2GDB):
    """
    This class represents malloc_chunk struct with interface compatible with `gdb.Value`.
    """

    _c_struct = c_malloc_chunk
    sizeof = ctypes.sizeof(_c_struct)


class c_tcache_perthread_struct_2_29(ctypes.LittleEndianStructure):
    """
    This class represents tcache_perthread_struct for GLIBC < 2.30 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.29/malloc/malloc.c#L2916

    typedef struct tcache_perthread_struct
    {
        char counts[TCACHE_MAX_BINS];
        tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    """

    _fields_ = [
        ("counts", ctypes.c_char * TCACHE_MAX_BINS),
        ("entries", c_pvoid * TCACHE_MAX_BINS),
    ]


class c_tcache_perthread_struct_2_30(ctypes.LittleEndianStructure):
    """
    This class represents the tcache_perthread_struct for GLIBC >= 2.30 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L3025

    typedef struct tcache_perthread_struct
    {
        uint16_t counts[TCACHE_MAX_BINS];
        tcache_entry *entries[TCACHE_MAX_BINS];
    } tcache_perthread_struct;
    """

    _fields_ = [
        ("counts", ctypes.c_uint16 * TCACHE_MAX_BINS),
        ("entries", c_pvoid * TCACHE_MAX_BINS),
    ]


class TcachePerthreadStruct(CStruct2GDB):
    """
    This class represents tcache_perthread_struct with interface compatible with `gdb.Value`.
    """

    if pwndbg.glibc.get_version() >= (2, 30):
        _c_struct = c_tcache_perthread_struct_2_30
    else:
        _c_struct = c_tcache_perthread_struct_2_29
    sizeof = ctypes.sizeof(_c_struct)


class c_tcache_entry_2_28(ctypes.LittleEndianStructure):
    """
    This class represents the tcache_entry struct for GLIBC < 2.29 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L2888

    typedef struct tcache_entry
    {
        struct tcache_entry *next;
    } tcache_entry;
    """

    _fields_ = [("next", c_pvoid)]


class c_tcache_entry_2_29(ctypes.LittleEndianStructure):
    """
    This class represents the tcache_entry struct for GLIBC >= 2.29 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.34/malloc/malloc.c#L3013

    typedef struct tcache_entry
    {
        struct tcache_entry *next;
        /* This field exists to detect double frees.  */
        uintptr_t key;
    } tcache_entry;
    """

    _fields_ = [("next", c_pvoid), ("key", c_pvoid)]


class TcacheEntry(CStruct2GDB):
    """
    This class represents the tcache_entry struct with interface compatible with `gdb.Value`.
    """

    if pwndbg.glibc.get_version() >= (2, 29):
        _c_struct = c_tcache_entry_2_29
    else:
        _c_struct = c_tcache_entry_2_28
    sizeof = ctypes.sizeof(_c_struct)


class c_malloc_par_2_25(ctypes.LittleEndianStructure):
    """
    This class represents the malloc_par struct for GLIBC < 2.26 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.25/malloc/malloc.c#L1690

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
    };
    """

    _fields_ = [
        ("trim_threshold", c_size_t),
        ("top_pad", c_size_t),
        ("mmap_threshold", c_size_t),
        ("arena_test", c_size_t),
        ("arena_max", c_size_t),
        ("n_mmaps", ctypes.c_int32),
        ("n_mmaps_max", ctypes.c_int32),
        ("max_n_mmaps", ctypes.c_int32),
        ("no_dyn_threshold", ctypes.c_int32),
        ("mmapped_mem", c_size_t),
        ("max_mmapped_mem", c_size_t),
        ("sbrk_base", c_pvoid),
    ]


class c_malloc_par_2_26(ctypes.LittleEndianStructure):
    """
    This class represents the malloc_par struct for GLIBC >= 2.26 as a ctypes struct.

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

    _fields_ = [
        ("trim_threshold", c_size_t),
        ("top_pad", c_size_t),
        ("mmap_threshold", c_size_t),
        ("arena_test", c_size_t),
        ("arena_max", c_size_t),
        ("n_mmaps", ctypes.c_int32),
        ("n_mmaps_max", ctypes.c_int32),
        ("max_n_mmaps", ctypes.c_int32),
        ("no_dyn_threshold", ctypes.c_int32),
        ("mmapped_mem", c_size_t),
        ("max_mmapped_mem", c_size_t),
        ("sbrk_base", c_pvoid),
        ("tcache_bins", c_size_t),
        ("tcache_max_bytes", c_size_t),
        ("tcache_count", ctypes.c_int32),
        ("tcache_unsorted_limit", c_size_t),
    ]


class c_malloc_par_2_35(ctypes.LittleEndianStructure):
    """
    This class represents the malloc_par struct for GLIBC >= 2.35 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.35/malloc/malloc.c#L1874

    struct malloc_par
    {
        /* Tunable parameters */
        unsigned long trim_threshold;
        INTERNAL_SIZE_T top_pad;
        INTERNAL_SIZE_T mmap_threshold;
        INTERNAL_SIZE_T arena_test;
        INTERNAL_SIZE_T arena_max;

    #if HAVE_TUNABLES
        /* Transparent Large Page support.  */
        INTERNAL_SIZE_T thp_pagesize;
        /* A value different than 0 means to align mmap allocation to hp_pagesize
            add hp_flags on flags.  */
        INTERNAL_SIZE_T hp_pagesize;
        int hp_flags;
    #endif

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

    _fields_ = [
        ("trim_threshold", c_size_t),
        ("top_pad", c_size_t),
        ("mmap_threshold", c_size_t),
        ("arena_test", c_size_t),
        ("arena_max", c_size_t),
        ("thp_pagesize", c_size_t),
        ("hp_pagesize", c_size_t),
        ("hp_flags", ctypes.c_int32),
        ("n_mmaps", ctypes.c_int32),
        ("n_mmaps_max", ctypes.c_int32),
        ("max_n_mmaps", ctypes.c_int32),
        ("no_dyn_threshold", ctypes.c_int32),
        ("mmapped_mem", c_size_t),
        ("max_mmapped_mem", c_size_t),
        ("sbrk_base", c_pvoid),
        ("tcache_bins", c_size_t),
        ("tcache_max_bytes", c_size_t),
        ("tcache_count", ctypes.c_int32),
        ("tcache_unsorted_limit", c_size_t),
    ]


class MallocPar(CStruct2GDB):
    """
    This class represents the malloc_par struct with interface compatible with `gdb.Value`.
    """

    if pwndbg.glibc.get_version() >= (2, 35):
        _c_struct = c_malloc_par_2_35
    elif pwndbg.glibc.get_version() >= (2, 26):
        _c_struct = c_malloc_par_2_26
    else:
        _c_struct = c_malloc_par_2_25
    sizeof = ctypes.sizeof(_c_struct)
