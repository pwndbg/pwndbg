from __future__ import annotations

import ctypes
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from typing import Type

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.glibc
from pwndbg.aglib.ctypes import Structure


def request2size(req: int) -> int:
    if req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE:
        return MINSIZE
    return (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK


def fastbin_index(size: int) -> int:
    if pwndbg.aglib.arch.ptrsize == 8:
        return (size >> 4) - 2
    else:
        return (size >> 3) - 2


GLIBC_VERSION = pwndbg.glibc.get_version()
# TODO: Move these heap constants and macros to elsewhere, because pwndbg/aglib/heap/ptmalloc.py also uses them, we are duplicating them here.
SIZE_SZ = pwndbg.aglib.arch.ptrsize
MINSIZE = pwndbg.aglib.arch.ptrsize * 4
if pwndbg.aglib.arch.name == "i386" and GLIBC_VERSION >= (2, 26):
    # i386 will override it to 16 when GLIBC version >= 2.26
    # See https://elixir.bootlin.com/glibc/glibc-2.26/source/sysdeps/i386/malloc-alignment.h#L22
    MALLOC_ALIGN = 16
else:
    # See https://elixir.bootlin.com/glibc/glibc-2.37/source/sysdeps/generic/malloc-alignment.h#L27
    long_double_alignment = pwndbg.aglib.typeinfo.lookup_types("long double").alignof
    MALLOC_ALIGN = long_double_alignment if 2 * SIZE_SZ < long_double_alignment else 2 * SIZE_SZ

MALLOC_ALIGN_MASK = MALLOC_ALIGN - 1
MAX_FAST_SIZE = 80 * SIZE_SZ // 4
NBINS = 128
BINMAPSIZE = 4
TCACHE_MAX_BINS = 64
NFASTBINS = fastbin_index(request2size(MAX_FAST_SIZE)) + 1

if pwndbg.aglib.arch.ptrsize == 4:
    PTR = ctypes.c_uint32
    SIZE_T = ctypes.c_uint32
else:
    PTR = ctypes.c_uint64  # type: ignore[misc]
    SIZE_T = ctypes.c_uint64  # type: ignore[misc]

DEFAULT_TOP_PAD = 131072
DEFAULT_MMAP_MAX = 65536
DEFAULT_MMAP_THRESHOLD = 128 * 1024
DEFAULT_TRIM_THRESHOLD = 128 * 1024
DEFAULT_PAGE_SIZE = 4096
TCACHE_FILL_COUNT = 7


class c_pvoid(PTR):
    """
    Represents a pointer.
    """


class c_size_t(SIZE_T):
    """
    Represents a size_t.
    """


C2GDB_MAPPING = {
    ctypes.c_char: pwndbg.aglib.typeinfo.char,
    ctypes.c_int8: pwndbg.aglib.typeinfo.int8,
    ctypes.c_int16: pwndbg.aglib.typeinfo.int16,
    ctypes.c_int32: pwndbg.aglib.typeinfo.int32,
    ctypes.c_int64: pwndbg.aglib.typeinfo.int64,
    ctypes.c_uint8: pwndbg.aglib.typeinfo.uint8,
    ctypes.c_uint16: pwndbg.aglib.typeinfo.uint16,
    ctypes.c_uint32: pwndbg.aglib.typeinfo.uint32,
    ctypes.c_uint64: pwndbg.aglib.typeinfo.uint64,
    c_pvoid: pwndbg.aglib.typeinfo.pvoid,
    c_size_t: pwndbg.aglib.typeinfo.size_t,
}

# Use correct endian for the dictionary keys
if pwndbg.aglib.arch.endian == "little":
    C2GDB_MAPPING: Dict[Type[ctypes.c_char], pwndbg.dbg_mod.Type] = {  # type: ignore[no-redef]
        k.__ctype_le__: v for k, v in C2GDB_MAPPING.items()
    }
else:
    C2GDB_MAPPING: Dict[Type[ctypes.c_char], pwndbg.dbg_mod.Type] = {  # type: ignore[no-redef]
        k.__ctype_be__: v for k, v in C2GDB_MAPPING.items()
    }


class FakeGDBField:
    """
    Fake gdb.Field for compatibility
    """

    def __init__(
        self,
        bitpos: int,
        name: str | None,
        type,
        parent_type,
        enumval: int | None = None,
        artificial: bool = False,
        is_base_class: bool = False,
        bitsize: int = 0,
    ) -> None:
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
    code = pwndbg.dbg_mod.TypeCode.STRUCT
    _c_struct: Type[ctypes.Structure]

    def __init__(self, address: int) -> None:
        self.address = address

    def __int__(self) -> int:
        """
        Returns the address of the C struct.
        """
        return self.address

    def __getitem__(self, key: str) -> pwndbg.dbg_mod.Value:
        """
        Returns the value of the specified field as a `pwndbg.dbg_mod.Value`.
        """
        return self.read_field(key)

    def __getattr__(self, key: str) -> pwndbg.dbg_mod.Value:
        """
        Returns the value of the specified field as a `pwndbg.dbg_mod.Value`.
        """
        return self.read_field(key)

    def __eq__(self, other: Any) -> bool:
        return self.address == int(other)

    def value_to_human_readable(self) -> str:
        """
        Returns a string representation of the C struct like `pwndbg.dbg_mod.Value` does.
        """
        output = "{\n"
        for f in self._c_struct._fields_:
            output += f"  {f[0]} = {self.read_field(f[0]).inner},\n"
        output += "}"
        return output

    def read_field(self, field: str) -> pwndbg.dbg_mod.Value:
        """
        Returns the value of the specified field as a `pwndbg.dbg_mod.Value`.
        """
        field_address = self.get_field_address(field)
        field_type = next(f for f in self._c_struct._fields_ if f[0] == field)[1]
        if hasattr(field_type, "_length_"):  # f is a ctypes Array
            t = C2GDB_MAPPING[field_type._type_]
            return pwndbg.aglib.memory.get_typed_pointer_value(
                t.array(field_type._length_), field_address
            )
        return pwndbg.aglib.memory.get_typed_pointer_value(C2GDB_MAPPING[field_type], field_address)

    @property
    def type(self):
        """
        Returns type(self) to make it compatible with the `pwndbg.dbg_mod.Value` interface.
        """
        return type(self)

    @classmethod
    def unqualified(cls):
        """
        Returns cls to make it compatible with the `gdb.types.has_field()` interface.
        """
        return cls

    @classmethod
    def fields(cls) -> List[FakeGDBField]:
        """
        Return fields of the struct to make it compatible with the `pwndbg.dbg_mod.Type` interface.
        """
        fake_gdb_fields: List[FakeGDBField] = []
        for f in cls._c_struct._fields_:
            field_name = f[0]
            field_type = f[1]
            bitpos = getattr(cls._c_struct, field_name).offset * 8
            if hasattr(field_type, "_length_"):  # f is a ctypes Array
                t = C2GDB_MAPPING[field_type._type_]
                _type = t.array(field_type._length_)
            else:
                _type = C2GDB_MAPPING[field_type]
            fake_gdb_fields.append(FakeGDBField(bitpos, field_name, _type, cls))
        return fake_gdb_fields

    @classmethod
    def keys(cls) -> List[str]:
        """
        Return a list of the names of the fields in the struct to make it compatible with the `pwndbg.dbg_mod.Type` interface.
        """
        return [f[0] for f in cls._c_struct._fields_]

    def get_field_address(self, field: str) -> int:
        """
        Returns the address of the specified field.
        """
        return self.address + getattr(self._c_struct, field).offset

    @classmethod
    def get_field_offset(cls, field: str) -> int:
        """
        Returns the offset of the specified field.
        """
        return getattr(cls._c_struct, field).offset

    def items(self) -> Tuple[Tuple[Any, Any], ...]:
        """
        Returns a tuple of (field name, field value) pairs.
        """
        return tuple((field[0], getattr(self, field[0])) for field in self._c_struct._fields_)

    @classmethod
    def has_field(self, field: str) -> bool:
        """
        Checks whether a field exists to make it compatible with the `pwndbg.dbg_mod.Type` interface.
        """
        return field in self.keys()


class c_malloc_state_2_26(Structure):
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


class c_malloc_state_2_12(Structure):
    """
    This class represents malloc_state struct for GLIBC < 2.22 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.12/malloc/malloc.c#L2362-L2400

    struct malloc_state {
    /* Serialize access.  */
    mutex_t mutex;

    /* Flags (formerly in max_fast).  */
    int flags;

    #if THREAD_STATS
    /* Statistics for locking.  Only used if THREAD_STATS is defined.  */
    long stat_lock_direct, stat_lock_loop, stat_lock_wait;
    #endif

    /* Fastbins */
    mfastbinptr      fastbinsY[NFASTBINS];

    /* Base of the topmost chunk -- not otherwise kept in a bin */
    mchunkptr        top;

    /* The remainder from the most recent split of a small request */
    mchunkptr        last_remainder;

    /* Normal bins packed as described above */
    mchunkptr        bins[NBINS * 2 - 2];

    /* Bitmap of bins */
    unsigned int     binmap[BINMAPSIZE];

    /* Linked list */
    struct malloc_state *next;

    #ifdef PER_THREAD
    /* Linked list for free arenas.  */
    struct malloc_state *next_free;
    #endif

    /* Memory allocated from the system in this arena.  */
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
    };"""

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
        ("system_mem", c_size_t),
        ("max_system_mem", c_size_t),
    ]


class c_malloc_state_2_27(Structure):
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
    This class represents malloc_state struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    if GLIBC_VERSION >= (2, 27):
        _c_struct = c_malloc_state_2_27
    elif GLIBC_VERSION >= (2, 23):
        _c_struct = c_malloc_state_2_26
    else:
        _c_struct = c_malloc_state_2_12
    sizeof = ctypes.sizeof(_c_struct)


class c_heap_info(Structure):
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
    This class represents heap_info struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    _c_struct = c_heap_info
    sizeof = ctypes.sizeof(_c_struct)


class c_malloc_chunk(Structure):
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
    This class represents malloc_chunk struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    _c_struct = c_malloc_chunk
    sizeof = ctypes.sizeof(_c_struct)


class c_tcache_perthread_struct_2_29(Structure):
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


class c_tcache_perthread_struct_2_30(Structure):
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
    This class represents tcache_perthread_struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    if GLIBC_VERSION >= (2, 30):
        _c_struct = c_tcache_perthread_struct_2_30
    else:
        _c_struct = c_tcache_perthread_struct_2_29
    sizeof = ctypes.sizeof(_c_struct)


class c_tcache_entry_2_28(Structure):
    """
    This class represents the tcache_entry struct for GLIBC < 2.29 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.28/malloc/malloc.c#L2888

    typedef struct tcache_entry
    {
        struct tcache_entry *next;
    } tcache_entry;
    """

    _fields_ = [("next", c_pvoid)]


class c_tcache_entry_2_29(Structure):
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
    This class represents the tcache_entry struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    if GLIBC_VERSION >= (2, 29):
        _c_struct = c_tcache_entry_2_29
    else:
        _c_struct = c_tcache_entry_2_28
    sizeof = ctypes.sizeof(_c_struct)


class c_malloc_par_2_23(Structure):
    """
    This class represents the malloc_par struct for GLIBC < 2.24 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.23/malloc/malloc.c#L1726

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
    /*INTERNAL_SIZE_T  sbrked_mem;*/
    /*INTERNAL_SIZE_T  max_sbrked_mem;*/
    INTERNAL_SIZE_T max_mmapped_mem;
    INTERNAL_SIZE_T max_total_mem;  /* only kept for NO_THREADS */

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
        ("max_total_mem", c_size_t),
        ("sbrk_base", c_pvoid),
    ]


class c_malloc_par_2_12(Structure):
    """
    This class represents the malloc_par struct for GLIBC < 2.15 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.12/malloc/malloc.c#L2402-L2433

    struct malloc_par {
    /* Tunable parameters */
    unsigned long    trim_threshold;
    INTERNAL_SIZE_T  top_pad;
    INTERNAL_SIZE_T  mmap_threshold;
    #ifdef PER_THREAD
    INTERNAL_SIZE_T  arena_test;
    INTERNAL_SIZE_T  arena_max;
    #endif

    /* Memory map support */
    int              n_mmaps;
    int              n_mmaps_max;
    int              max_n_mmaps;
    /* the mmap_threshold is dynamic, until the user sets
        it manually, at which point we need to disable any
        dynamic behavior. */
    int              no_dyn_threshold;

    /* Cache malloc_getpagesize */
    unsigned int     pagesize;

    /* Statistics */
    INTERNAL_SIZE_T  mmapped_mem;
    /*INTERNAL_SIZE_T  sbrked_mem;*/
    /*INTERNAL_SIZE_T  max_sbrked_mem;*/
    INTERNAL_SIZE_T  max_mmapped_mem;
    INTERNAL_SIZE_T  max_total_mem; /* only kept for NO_THREADS */

    /* First address handed out by MORECORE/sbrk.  */
    char*            sbrk_base;
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
        ("pagesize", c_size_t),
        ("mmapped_mem", c_size_t),
        ("max_mmapped_mem", c_size_t),
        ("max_total_mem", c_size_t),
        ("sbrk_base", c_pvoid),
    ]


class c_malloc_par_2_24(Structure):
    """
    This class represents the malloc_par struct for GLIBC >= 2.24 as a ctypes struct.

    https://github.com/bminor/glibc/blob/glibc-2.25/malloc/malloc.c#L1690
    https://github.com/bminor/glibc/blob/glibc-2.24/malloc/malloc.c#L1719

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


class c_malloc_par_2_26(Structure):
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
        ("tcache_count", c_size_t),
        ("tcache_unsorted_limit", c_size_t),
    ]


class c_malloc_par_2_35(Structure):
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
        ("tcache_count", c_size_t),
        ("tcache_unsorted_limit", c_size_t),
    ]


class MallocPar(CStruct2GDB):
    """
    This class represents the malloc_par struct with interface compatible with `pwndbg.dbg_mod.Value`.
    """

    if GLIBC_VERSION >= (2, 35):
        _c_struct = c_malloc_par_2_35
    elif GLIBC_VERSION >= (2, 26):
        _c_struct = c_malloc_par_2_26
    elif GLIBC_VERSION >= (2, 24):
        _c_struct = c_malloc_par_2_24
    elif GLIBC_VERSION >= (2, 15):
        _c_struct = c_malloc_par_2_23
    else:
        _c_struct = c_malloc_par_2_12
    sizeof = ctypes.sizeof(_c_struct)


# https://github.com/bminor/glibc/blob/glibc-2.37/malloc/malloc.c#L1911-L1926
# static struct malloc_par mp_ =
# {
#   .top_pad = DEFAULT_TOP_PAD,
#   .n_mmaps_max = DEFAULT_MMAP_MAX,
#   .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
#   .trim_threshold = DEFAULT_TRIM_THRESHOLD,
# #define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
#   .arena_test = NARENAS_FROM_NCORES (1)
# #if USE_TCACHE
#   ,
#   .tcache_count = TCACHE_FILL_COUNT,
#   .tcache_bins = TCACHE_MAX_BINS,
#   .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
#   .tcache_unsorted_limit = 0 /* No limit.  */
# #endif
# };
DEFAULT_MP_ = MallocPar._c_struct()
DEFAULT_MP_.top_pad = DEFAULT_TOP_PAD
DEFAULT_MP_.n_mmaps_max = DEFAULT_MMAP_MAX
DEFAULT_MP_.mmap_threshold = DEFAULT_MMAP_THRESHOLD
DEFAULT_MP_.trim_threshold = DEFAULT_TRIM_THRESHOLD
DEFAULT_MP_.arena_test = 2 if pwndbg.aglib.arch.ptrsize == 4 else 8
if (MallocPar._c_struct != c_malloc_par_2_23) and (MallocPar._c_struct != c_malloc_par_2_12):
    # the only difference between 2.23 and the rest is the lack of tcache
    DEFAULT_MP_.tcache_count = TCACHE_FILL_COUNT
    DEFAULT_MP_.tcache_bins = TCACHE_MAX_BINS
    DEFAULT_MP_.tcache_max_bytes = (TCACHE_MAX_BINS - 1) * MALLOC_ALIGN + MINSIZE - SIZE_SZ
if MallocPar._c_struct == c_malloc_par_2_12:
    DEFAULT_MP_.pagesize = DEFAULT_PAGE_SIZE
