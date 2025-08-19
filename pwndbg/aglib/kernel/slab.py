from __future__ import annotations

from typing import Generator
from typing import List
from typing import Set
from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.color.message as M
from pwndbg.aglib import kernel
from pwndbg.aglib.kernel.macros import compound_head
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.aglib.kernel.macros import swab


def caches() -> Generator[SlabCache, None, None]:
    slab_caches = pwndbg.aglib.kernel.slab_caches()
    if slab_caches is None:
        # Symbol not found
        return

    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        yield SlabCache(slab_cache)


def get_cache(target_name: str) -> SlabCache | None:
    slab_caches = pwndbg.aglib.kernel.slab_caches()
    if slab_caches is None:
        # Symbol not found
        return None

    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        if target_name == slab_cache["name"].string():
            return SlabCache(slab_cache)
    return None


def slab_struct_type() -> str:
    # In Linux kernel version 5.17 a slab struct was introduced instead of the previous page struct
    if pwndbg.aglib.kernel.krelease() >= (5, 17):
        return "slab"
    return "page"


OO_SHIFT = 16
OO_MASK = (1 << OO_SHIFT) - 1


def oo_order(x: int) -> int:
    return int(x) >> OO_SHIFT


def oo_objects(x: int) -> int:
    return int(x) & OO_MASK


_flags = {
    "SLAB_DEBUG_FREE": 0x00000100,
    "SLAB_RED_ZONE": 0x00000400,
    "SLAB_POISON": 0x00000800,
    "SLAB_HWCACHE_ALIGN": 0x00002000,
    "SLAB_CACHE_DMA": 0x00004000,
    "SLAB_STORE_USER": 0x00010000,
    "SLAB_RECLAIM_ACCOUNT": 0x00020000,
    "SLAB_PANIC": 0x00040000,
    "SLAB_DESTROY_BY_RCU": 0x00080000,
    "SLAB_MEM_SPREAD": 0x00100000,
    "SLAB_TRACE": 0x00200000,
    "SLAB_DEBUG_OBJECTS": 0x00400000,
    "SLAB_NOLEAKTRACE": 0x00800000,
    "SLAB_NOTRACK": 0x01000000,
    "SLAB_FAILSLAB": 0x02000000,
}


def get_flags_list(flags: int) -> List[str]:
    return [flag_name for flag_name, mask in _flags.items() if flags & mask]


class Freelist:
    def __init__(self, start_addr: int, offset: int, random: int = 0) -> None:
        self.start_addr = start_addr
        self.offset = offset
        self.random = random

    def __iter__(self) -> Generator[int, None, None]:
        seen: set[int] = set()
        current_object = self.start_addr
        while current_object:
            try:
                addr = int(current_object)
            except Exception:
                print(
                    M.warn(
                        f"Corrupted slab freelist detected at {hex(current_object)} when length is {len(seen)}"
                    )
                )
                break
            yield current_object
            current_object = pwndbg.aglib.memory.read_pointer_width(addr + self.offset)
            if self.random:
                current_object ^= self.random ^ swab(addr + self.offset)
            if addr in seen:
                # this can happen during exploit dev
                print(
                    M.warn(
                        f"Cyclic slab freelist detected at {hex(addr)} when length is {len(seen)}"
                    )
                )
                break
            seen.add(addr)

    def __int__(self) -> int:
        return self.start_addr

    def __len__(self) -> int:
        seen: set[int] = set()
        for addr in self:
            if addr in seen:
                # this can happen during exploit dev
                print(
                    M.warn(
                        f"Cyclic slab freelist detected at {hex(addr)} when length is {len(seen)}"
                    )
                )
                break
            seen.add(addr)
        return len(seen)

    def find_next(self, addr: int) -> int:
        freelist_iter = iter(self)
        for obj in freelist_iter:
            if obj == addr:
                return next(freelist_iter, 0)
        return 0


class SlabCache:
    def __init__(self, slab_cache: pwndbg.dbg_mod.Value) -> None:
        self._slab_cache = slab_cache

    @property
    def address(self) -> int:
        return int(self._slab_cache)

    @property
    def name(self) -> str:
        return self._slab_cache["name"].string()

    @property
    def offset(self) -> int:
        return int(self._slab_cache["offset"])

    @property
    def random(self) -> int:
        return (
            int(self._slab_cache["random"]) if "SLAB_FREELIST_HARDENED" in kernel.kconfig() else 0
        )

    @property
    def size(self) -> int:
        return int(self._slab_cache["size"])

    @property
    def slab_size(self) -> int:
        return 0x1000 << self.oo_order

    @property
    def object_size(self) -> int:
        return int(self._slab_cache["object_size"])

    @property
    def align(self) -> int:
        return int(self._slab_cache["align"])

    @property
    def flags(self) -> List[str]:
        return get_flags_list(int(self._slab_cache["flags"]))

    @property
    def cpu_cache(self) -> CpuCache | None:
        """returns cpu cache associated to current thread"""
        if not self._slab_cache.dereference().type.has_field("cpu_slab"):
            return None
        cpu = pwndbg.dbg.selected_thread().index() - 1
        cpu_cache = kernel.per_cpu(self._slab_cache["cpu_slab"], cpu=cpu)
        return CpuCache(cpu_cache, self, cpu)

    @property
    def cpu_caches(self) -> Generator[CpuCache, None, None]:
        if not self._slab_cache.dereference().type.has_field("cpu_slab"):
            return
        """returns cpu caches for all cpus"""
        for cpu in range(kernel.nproc()):
            cpu_cache = kernel.per_cpu(self._slab_cache["cpu_slab"], cpu=cpu)
            yield CpuCache(cpu_cache, self, cpu)

    @property
    def node_caches(self) -> Generator[NodeCache, None, None]:
        """returns node caches for all NUMA nodes"""
        for node in range(kernel.num_numa_nodes()):
            yield NodeCache(self._slab_cache["node"][node], self, node)

    @property
    def cpu_partial(self) -> int:
        if not self._slab_cache.dereference().type.has_field("cpu_partial"):
            return None
        return int(self._slab_cache["cpu_partial"])

    @property
    def cpu_partial_slabs(self) -> int:
        if self._slab_cache.dereference().type.has_field(f"cpu_partial_{slab_struct_type()}s"):
            return int(self._slab_cache[f"cpu_partial_{slab_struct_type()}s"])
        return None

    @property
    def min_partial(self) -> int:
        return int(self._slab_cache["min_partial"])

    @property
    def inuse(self) -> int:
        # somewhat mirrors libslub's implementation
        # looks for per_cpu active lists and per_cpu and node partial lists
        # no good way to track full slabs unless CONFIG_SLUB_DEBUG is enabled
        #       which is typically not from what I have seen
        cnt = 0
        for cpu_cache in self.cpu_caches:
            if cpu_cache.active_slab is not None:
                cnt += cpu_cache.active_slab.inuse
            for partial_slab in cpu_cache.partial_slabs:
                cnt += partial_slab.inuse
        for node_cache in self.node_caches:
            for partial_slab in node_cache.partial_slabs:
                cnt += partial_slab.inuse
        return cnt

    @property
    def useroffset(self) -> int:
        if not self._slab_cache.dereference().type.has_field("useroffset"):
            return None
        return int(self._slab_cache["useroffset"])

    @property
    def usersize(self) -> int:
        if not self._slab_cache.dereference().type.has_field("usersize"):
            return None
        return int(self._slab_cache["usersize"])

    @property
    def __oo_x(self) -> int:
        return int(self._slab_cache["oo"]["x"])

    @property
    def oo_order(self):
        return oo_order(self.__oo_x)

    @property
    def oo_objects(self):
        return oo_objects(self.__oo_x)

    def find_containing_slab(self, address) -> Slab | None:
        for cpu_cache in self.cpu_caches:
            slab = cpu_cache.active_slab
            if slab is not None and address in slab:
                return slab
            for slab in cpu_cache.partial_slabs:
                if slab is not None and address in slab:
                    return slab
        for node_cache in self.node_caches:
            for slab in node_cache.partial_slabs:
                if slab is not None and address in slab:
                    return slab
        return None


class CpuCache:
    def __init__(self, cpu_cache: pwndbg.dbg_mod.Value, slab_cache: SlabCache, cpu: int) -> None:
        self._cpu_cache = cpu_cache
        self.slab_cache = slab_cache
        self.cpu = cpu

    @property
    def address(self) -> int:
        return int(self._cpu_cache)

    @property
    def freelist(self) -> Freelist:
        return Freelist(
            int(self._cpu_cache["freelist"]),
            self.slab_cache.offset,
            self.slab_cache.random,
        )

    @property
    def active_slab(self) -> Slab | None:
        slab_key = slab_struct_type()
        _slab = self._cpu_cache[slab_key]
        if not int(_slab):
            return None
        return Slab(_slab.dereference(), self, None)

    @property
    def partial_slabs(self) -> List[Slab]:
        partial_slabs = []
        if not self._cpu_cache.dereference().type.has_field("partial"):
            return []
        cur_slab = self._cpu_cache["partial"]
        cur_slab_int = int(cur_slab)
        while cur_slab_int:
            _slab = cur_slab.dereference()
            partial_slabs.append(Slab(_slab, self, None, is_partial=True))
            cur_slab = _slab["next"]
            cur_slab_int = int(cur_slab)
        return partial_slabs


class NodeCache:
    def __init__(self, node_cache: pwndbg.dbg_mod.Value, slab_cache: SlabCache, node: int) -> None:
        self._node_cache = node_cache
        self.slab_cache = slab_cache
        self.node = node

    @property
    def address(self) -> int:
        return int(self._node_cache)

    @property
    def partial_slabs(self) -> List[Slab]:
        ret = []
        for slab in for_each_entry(
            self._node_cache["partial"], f"struct {slab_struct_type()}", "slab_list"
        ):
            ret.append(Slab(slab.dereference(), None, self, is_partial=True))
        return ret

    @property
    def nr_partial(self) -> int:
        return int(self._node_cache["nr_partial"])

    @property
    def min_partial(self) -> int:
        return self.slab_cache.min_partial


class Slab:
    def __init__(
        self,
        slab: pwndbg.dbg_mod.Value,
        cpu_cache: CpuCache | None,
        node_cache: NodeCache | None,
        is_partial: bool = False,
    ) -> None:
        self._slab = slab
        self.cpu_cache = cpu_cache
        self.node_cache = node_cache
        self.is_partial = is_partial
        self.is_cpu = False
        self.slab_cache = None
        if cpu_cache is not None:
            self.is_cpu = True
            self.slab_cache = cpu_cache.slab_cache
            assert node_cache is None
        if node_cache is not None:
            self.slab_cache = node_cache.slab_cache

    @property
    def slab_address(self) -> int:
        return int(self._slab.address)

    @property
    def virt_address(self) -> int:
        return kernel.page_to_virt(self.slab_address)

    @property
    def object_count(self) -> int:
        return int(self._slab["objects"])

    @property
    def objects(self) -> Generator[int, None, None]:
        size = self.slab_cache.size
        start = self.virt_address
        end = start + self.object_count * size
        return (i for i in range(start, end, size))

    @property
    def frozen(self) -> int:
        return int(self._slab["frozen"])

    @property
    def inuse(self) -> int:
        inuse = int(self._slab["inuse"])
        if not self.is_partial:
            # I believe only the cpu freelist is considered "inuse" similar to glibc's tcache
            inuse -= len(self.cpu_cache.freelist)
        return inuse

    @property
    def slabs(self) -> int:
        return int(self._slab[f"{slab_struct_type()}s"])

    @property
    def pobjects(self) -> int:
        if not self.is_partial:
            return 0
        if self._slab.type.has_field("pobjects"):
            return int(self._slab["pobjects"])
        else:
            # calculate approx obj count in half-full slabs (as done in kernel)
            # Note, this is a very bad approximation and could/should probably
            # be replaced by a more accurate method
            return (self.slabs * self.slab_cache.oo_objects) // 2

    @property
    def freelist(self) -> Freelist:
        return Freelist(
            int(self._slab["freelist"]),
            self.slab_cache.offset,
            self.slab_cache.random,
        )

    @property
    def freelists(self) -> List[Freelist]:
        freelists = [self.freelist]
        if not self.is_partial:
            freelists.append(self.cpu_cache.freelist)
        return freelists

    @property
    def free_objects(self) -> Set[int]:
        return {obj for freelist in self.freelists for obj in freelist}

    def __contains__(self, addr: int):
        return self.virt_address <= addr < self.virt_address + self.slab_cache.slab_size


def find_containing_slab_cache(addr: int) -> SlabCache | None:
    page = pwndbg.aglib.memory.get_typed_pointer_value("struct page", kernel.virt_to_page(addr))
    head_page = compound_head(page)

    slab_type = pwndbg.aglib.typeinfo.load(f"struct {slab_struct_type()}")
    assert slab_type is not None, "Symbol slab not found"

    slab = head_page.cast(slab_type)
    return SlabCache(slab["slab_cache"])


#########################################
# structurs relevant to slab
#
#########################################


def kmem_cache_node_pad_sz(val):
    for j in range(8):
        nr_partial = pwndbg.aglib.memory.u32(val)
        next = pwndbg.aglib.memory.u64(val + 0x8)
        prev = pwndbg.aglib.memory.u64(val + 0x10)
        val += 0x8
        if (
            nr_partial < 0x20
            and pwndbg.aglib.memory.is_kernel(next)
            and pwndbg.aglib.memory.is_kernel(prev)
        ):
            return j * 8
    return None


def kmem_cache_pad_sz(kconfig) -> Tuple[int, int]:
    # find the distance between the first kmem_cache's name and its first node cache
    # the name for the first kmem_cache (most likely) has the name "kmem_cache"
    # and the global var is also named "kmem_cache"
    name = "kmem_cache"
    name_off = None
    slab_caches = pwndbg.aglib.kernel.slab_caches()
    assert slab_caches, "can't find slab_caches"
    kmem_cache = int(slab_caches["prev"]) & ~0xFF
    for i in range(0x20):
        val = pwndbg.aglib.memory.u64(kmem_cache + i * 8)
        if pwndbg.aglib.memory.string(val) == name.encode():
            name_off = i * 8
            break
    assert name_off, "can't determine kmem_cache name offset"
    if pwndbg.aglib.kernel.krelease() >= (6, 2) and all(
        config not in kconfig
        for config in (
            "CONFIG_HARDENED_USERCOPY",
            "CONFIG_KASAN",
        )
    ):
        if all(
            config not in kconfig
            for config in (
                "CONFIG_SYSFS",
                "CONFIG_SLAB_FREELIST_HARDENED",
                "CONFIG_NUMA",
            )
        ):
            node_cache_pad = kmem_cache_node_pad_sz(
                kmem_cache + name_off + 0x8 * 3
            )  # name ptr + 2 list ptrs
            assert node_cache_pad, "can't determine kmem cache node padding size"
            distance = 8 if "CONFIG_SLAB_FREELIST_RANDOM" in kconfig else 0
            return distance, node_cache_pad
        elif "CONFIG_SLAB_FREELIST_RANDOM" in kconfig:
            for i in range(3, 0x20):
                ptr = kmem_cache + name_off + i * 8
                val = pwndbg.aglib.memory.u64(ptr)
                if pwndbg.aglib.memory.is_kernel(val):
                    distance = (i + 1) * 8
                    node_cache_pad = kmem_cache_node_pad_sz(kmem_cache + name_off + distance)
                    assert node_cache_pad, "can't determine kmem cache node padding size"
                    return distance, node_cache_pad
    distance, node_cache_pad = None, None
    for i in range(3, 0x20):
        ptr = kmem_cache + name_off + i * 8
        val = pwndbg.aglib.memory.u64(ptr - 8)
        if pwndbg.aglib.memory.peek(val) is not None:
            continue
        val = pwndbg.aglib.memory.u64(ptr)
        if pwndbg.aglib.memory.peek(val) is None:
            continue
        node_cache_pad = kmem_cache_node_pad_sz(val)
        if node_cache_pad is not None:
            distance = i * 8
            break
    assert distance, "can't find kmem_cache node"
    distance -= 0x18  # the name ptr + list_head
    configs = (
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_NUMA",
        "CONFIG_SLAB_FREELIST_RANDOM",
    )
    for config in configs:
        if config in kconfig:
            distance -= 8
    if pwndbg.aglib.kernel.krelease() >= (6, 3):
        distance -= 8 if "CONFIG_KASAN_GENERIC" in kconfig else 0
    else:
        distance -= 8 if "CONFIG_KASAN" in kconfig else 0
    if "CONFIG_HARDENED_USERCOPY" in kconfig or pwndbg.aglib.kernel.krelease() < (6, 2):
        distance -= 8
    assert distance < 0x1000, "cannot find kmem_cache padding size"
    return distance, node_cache_pad


def kmem_cache_structs(node_cache_pad):
    if pwndbg.aglib.kernel.symbol.kversion_cint() is None:
        return
    result = f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    if "CONFIG_SLUB_CPU_PARTIAL" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_SLUB_CPU_PARTIAL\n"
    result += f"""
    struct kmem_cache_node {{
        char _pad[{node_cache_pad}];
        unsigned long nr_partial;
        struct list_head partial;
    }};
    """
    result += """
    struct kasan_cache {
#if !((KERNEL_VERSION(6, 1, 0) <= KVERSION && KVERSION < KERNEL_VERSION(6, 3, 0)))
        int alloc_meta_offset;
        int free_meta_offset;
#elif defined(CONFIG_KASAN_GENERIC)
        int alloc_meta_offset;
        int free_meta_offset;
#endif
#if KERNEL_VERSION(5, 12, 0) <= KVERSION && KVERSION < KERNEL_VERSION(6, 3, 0)
        bool is_kmalloc;
#endif
    };
    struct kmem_cache_order_objects {
        unsigned int x;
    };
    struct reciprocal_value {
        u32 m;
        u8 sh1, sh2;
    };
    typedef unsigned int gfp_t;
    typedef unsigned int slab_flags_t;
#if KVERSION >= KERNEL_VERSION(5, 17, 0)
    struct slab {
        unsigned long __page_flags;
#if KVERSION >= KERNEL_VERSION(6, 2, 0)
        struct kmem_cache *slab_cache;
#endif
        union {
            struct list_head slab_list;
#ifdef CONFIG_SLUB_CPU_PARTIAL
            struct {
                struct slab *next;
                int slabs;	/* Nr of slabs left */
            };
#endif
        };
#if KVERSION < KERNEL_VERSION(6, 2, 0)
        struct kmem_cache *slab_cache;
#endif
        void *freelist;		/* first free object */
        union {
            unsigned long counters;
            struct {
                unsigned inuse:16;
                unsigned objects:15;
                unsigned frozen:1;
            };
        };
        // rcu_head in later versions is not important for our purposes
        unsigned int __page_type;
        atomic_t __page_refcount;
        /* memcg data unused in pwndbg */
    };
#endif
    """
    result += f"""
    struct kmem_cache_cpu {{
        void **freelist;	/* Pointer to next available object */
        unsigned long tid;	/* Globally unique transaction id */
        struct {slab_struct_type()} *{slab_struct_type()};	/* The slab from which we are allocating */
#ifdef CONFIG_SLUB_CPU_PARTIAL
        struct {slab_struct_type()} *partial;	/* Partially allocated frozen slabs */
#endif
        /* irrelevant fields*/
    }};
    """
    return result


def load_slab_typeinfo():
    if pwndbg.aglib.typeinfo.lookup_types("struct kmem_cache") is not None:
        return
    if pwndbg.aglib.kernel.symbol.kversion_cint() is None:
        return
    pwndbg.aglib.kernel.symbol.load_common_structs()
    kconfig = pwndbg.aglib.kernel.kconfig()
    defs = []
    configs = (
        "CONFIG_SLUB_TINY",
        "CONFIG_SLUB_CPU_PARTIAL",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_NUMA",
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_KASAN_GENERIC",
        "CONFIG_HARDENED_USERCOPY",
        "CONFIG_KASAN",
    )
    for config in configs:
        if config in kconfig:
            defs.append(config)
    sz, node_cache_pad = kmem_cache_pad_sz(kconfig)
    result = f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    result += "\n".join(f"#define {s}" for s in defs)
    result += pwndbg.aglib.kernel.symbol.COMMON_TYPES
    result += kmem_cache_structs(node_cache_pad)
    # this is the kmem_cache SLUB representation for all 5.x and 6.x
    result += f"""
    struct kmem_cache {{
#if !defined(CONFIG_SLUB_TINY) || KVERSION < KERNEL_VERSION(6, 2, 0)
        struct kmem_cache_cpu *cpu_slab;
#endif
        /* Used for retrieving partial slabs, etc. */
        slab_flags_t flags;
        unsigned long min_partial;
        unsigned int size;		/* Object size including metadata */
        unsigned int object_size;	/* Object size without metadata */
#if KVERSION >= KERNEL_VERSION(5, 9, 0)
        struct reciprocal_value reciprocal_size;
#endif
        unsigned int offset;		/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
        /* Number of per cpu partial objects to keep around */
        unsigned int cpu_partial;
#if KVERSION >= KERNEL_VERSION(5, 16, 0)
        /* Number of per cpu partial slabs to keep around */
        unsigned int cpu_partial_{slab_struct_type()}s;
#endif
#endif
        struct kmem_cache_order_objects oo;
        /* Allocation and freeing of slabs */
        struct kmem_cache_order_objects min;
#if KVERSION < KERNEL_VERSION(5, 19, 0)
        struct kmem_cache_order_objects max;
#endif
        gfp_t allocflags;		/* gfp flags to use on each alloc */
        int refcount;			/* Refcount for slab cache destroy */
        void *ctor;	            /* Object constructor -- ignoring possible args */
        unsigned int inuse;		/* Offset to metadata */
        unsigned int align;		/* Alignment */
        unsigned int red_left_pad;	/* Left redzone padding size */
        const char *name;		/* Name (only for display!) */
        struct list_head list;		/* List of slab caches */

        char _pad1[{sz}]; // collapse the struct(s) that are version dependent and complex
#ifdef CONFIG_SLAB_FREELIST_HARDENED
        unsigned long random;
#endif
#ifdef CONFIG_NUMA
        unsigned int remote_node_defrag_ratio;
#endif
#ifdef CONFIG_SLAB_FREELIST_RANDOM
        unsigned int *random_seq;
#endif
#if (KVERSION >= KERNEL_VERSION(6, 3, 0) && defined(CONFIG_KASAN_GENERIC) || (KVERSION < KERNEL_VERSION(6, 3, 0) && defined(CONFIG_KASAN)))
        struct kasan_cache kasan_info;
#endif
#if KVERSION < KERNEL_VERSION(6, 2, 0) || defined(CONFIG_HARDENED_USERCOPY)
        unsigned int useroffset;	/* Usercopy region offset */
        unsigned int usersize;		/* Usercopy region size */
#endif
        // ensure it has at least num_numa_nodes, sufficient for us
        struct kmem_cache_node *node[{pwndbg.aglib.kernel.num_numa_nodes()}];
    }};
    """
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "slab_structs", True)
