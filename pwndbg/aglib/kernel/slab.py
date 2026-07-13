from __future__ import annotations

from collections.abc import Generator

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg.aglib import kernel
from pwndbg.aglib.kernel.macros import compound_head
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.aglib.kernel.macros import memdesc_flag_or_int
from pwndbg.aglib.kernel.macros import swab


def caches() -> Generator[SlabCache, None, None]:
    recover_slab_typeinfo()
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
    krelease = kernel.krelease()
    if krelease and krelease >= (5, 17):
        return "slab"
    return "page"


def slab_list_field() -> str:
    # In kernels older than 4.18, struct page uses 'lru' instead of 'slab_list' for the node partial slab list.
    page_type = pwndbg.aglib.typeinfo.load(f"struct {slab_struct_type()}")
    if page_type is not None and page_type.offsetof("slab_list") is not None:
        return "slab_list"
    return "lru"


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


def get_flags_list(flags: int) -> list[str]:
    return [flag_name for flag_name, mask in _flags.items() if flags & mask]


class Freelist:
    def __init__(self, start_addr: int, slab: Slab | None) -> None:
        self.start_addr = start_addr
        self.slab = slab
        if not self.slab:
            return
        self.offset = self.slab.slab_cache.offset
        self.random = self.slab.slab_cache.random
        self.cyclic = None

    def __iter__(self) -> Generator[int, None, None]:
        if not self.slab:
            return
        seen: set[int] = set()
        curr = None
        next = self.start_addr
        while next:
            if next in seen:
                self.cyclic = curr
                return
            if not pwndbg.aglib.memory.is_kernel(next + self.offset):
                break
            if next not in self.slab or not self.is_valid_obj(next):
                break
            curr = next
            next = self.find_next(curr)
            yield curr
            seen.add(curr)
        # reaching here means the freelist is not cyclic (prior to detections of other corruptions)
        self.cyclic = None

    def __int__(self) -> int:
        return self.start_addr

    def __len__(self) -> int:
        return sum(1 for _ in self)

    def find_next(self, addr: int) -> int:
        # assumes addr is in this freelist -> assert(addr in self)
        # caller should assert this behaviour to avoid traversing the list unnecessarily
        if not self.slab:
            raise ValueError("slab freelist must belong to a slab")
        next = pwndbg.aglib.memory.read_pointer_width(addr + self.offset)
        if self.random:
            next ^= self.random ^ swab(addr + self.offset)
        return next

    def is_valid_obj(self, addr: int) -> bool:
        if not self.slab:
            return False
        diff = addr - self.slab.virt_address
        sz = self.slab.slab_cache.size
        return diff % sz == 0 and 0 <= (diff // sz) < self.slab.object_count


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
        return kernel.page_size() << self.oo_order

    @property
    def object_size(self) -> int:
        return int(self._slab_cache["object_size"])

    @property
    def align(self) -> int:
        return int(self._slab_cache["align"])

    @property
    def flags(self) -> list[str]:
        return get_flags_list(memdesc_flag_or_int(self._slab_cache["flags"]))

    @property
    def cpu_cache(self) -> CpuCache | None:
        """returns cpu cache associated to current thread"""
        if not self._slab_cache.dereference().type.has_field("cpu_slab"):
            return None
        cpu = pwndbg.aglib.kernel.current_cpu()
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
        if kernel.krelease() >= (7, 1):
            for node in range(kernel.num_numa_nodes()):
                yield NodeCache(self._slab_cache["per_node"][node]["node"], self, node)
        else:
            for node in range(kernel.num_numa_nodes()):
                yield NodeCache(self._slab_cache["node"][node], self, node)

    @property
    def cpu_partial(self) -> int | None:
        if not self._slab_cache.dereference().type.has_field("cpu_partial"):
            return None
        return int(self._slab_cache["cpu_partial"])

    @property
    def cpu_partial_slabs(self) -> int | None:
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
    def useroffset(self) -> int | None:
        if not self._slab_cache.dereference().type.has_field("useroffset"):
            return None
        return int(self._slab_cache["useroffset"])

    @property
    def usersize(self) -> int | None:
        if not self._slab_cache.dereference().type.has_field("usersize"):
            return None
        return int(self._slab_cache["usersize"])

    @property
    def __oo_x(self) -> int:
        return int(self._slab_cache["oo"]["x"])

    @property
    def oo_order(self) -> int:
        return oo_order(self.__oo_x)

    @property
    def oo_objects(self) -> int:
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
        return Freelist(int(self._cpu_cache["freelist"]), self.active_slab)

    @property
    def active_slab(self) -> Slab | None:
        slab_key = slab_struct_type()
        _slab = self._cpu_cache[slab_key]
        if not int(_slab):
            return None
        return Slab(_slab.dereference(), cpu_cache=self, is_active=True)

    @property
    def partial_slabs(self) -> list[Slab]:
        partial_slabs = []
        if not self._cpu_cache.dereference().type.has_field("partial"):
            return []
        cur_slab = self._cpu_cache["partial"]
        cur_slab_int = int(cur_slab)
        while cur_slab_int:
            _slab = cur_slab.dereference()
            partial_slabs.append(Slab(_slab, cpu_cache=self))
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
    def partial_slabs(self) -> list[Slab]:
        ret = []
        for slab in for_each_entry(
            self._node_cache["partial"], f"struct {slab_struct_type()}", slab_list_field()
        ):
            ret.append(Slab(slab.dereference(), node_cache=self))
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
        cpu_cache: CpuCache | None = None,
        node_cache: NodeCache | None = None,
        is_active: bool = False,
    ) -> None:
        self._slab = slab
        address = slab.address
        assert address
        self.slab_address = int(address)
        self.is_active = is_active
        if cpu_cache is not None:
            self.cpu_cache = cpu_cache
            self.is_cpu = True
            self.slab_cache = cpu_cache.slab_cache
        elif node_cache is not None:
            self.node_cache = node_cache
            self.is_cpu = False
            self.slab_cache = node_cache.slab_cache

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def virt_address(self) -> int:
        if "CONFIG_SLAB_VIRTUAL" not in kernel.kconfig():
            return kernel.page_to_virt(self.slab_address)
        return kernel.slab_to_virt(self.slab_address)

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
        if self.is_active:
            # only the cpu freelist is considered "inuse" similar to glibc's tcache
            inuse -= len(self.cpu_cache.freelist)
        return inuse

    @property
    def slabs(self) -> int:
        return int(self._slab[f"{slab_struct_type()}s"])

    @property
    def pobjects(self) -> int:
        if self.is_active:
            return 0
        if self._slab.type.has_field("pobjects"):
            return int(self._slab["pobjects"])
        # calculate approx obj count in half-full slabs (as done in kernel)
        # Note, this is a very bad approximation and could/should probably
        # be replaced by a more accurate method
        return (self.slabs * self.slab_cache.oo_objects) // 2

    @property
    def freelist(self) -> Freelist:
        return Freelist(int(self._slab["freelist"]), self)

    @property
    def free_objects(self) -> set[int]:
        result = set()
        for obj in self.freelist:
            result.add(obj)
        if self.is_active and self.cpu_cache.freelist:
            for obj in self.cpu_cache.freelist:
                result.add(obj)
        return result

    def __contains__(self, addr: int):
        return self.virt_address <= addr < self.virt_address + self.slab_cache.slab_size


def find_containing_slab_cache(addr: int) -> tuple[int | None, SlabCache | None]:
    recover_slab_typeinfo()  # throws a separate exception
    try:
        if "CONFIG_SLAB_VIRTUAL" not in kernel.kconfig():
            page = pwndbg.aglib.memory.get_typed_pointer_value(
                "struct page", kernel.virt_to_page(addr)
            )
            head_page = compound_head(page)
            address = head_page.address
            assert address
            base = kernel.page_to_virt(int(address))
            slab_type = pwndbg.aglib.typeinfo.load(f"struct {slab_struct_type()}")
            slab = head_page.cast(slab_type)
        else:
            _slab = kernel.virt_to_slab(addr)
            base = kernel.slab_to_virt(_slab)
            # mitigations are recent enough that the struct is expected to exist
            slab = pwndbg.aglib.memory.get_typed_pointer_value("struct slab", _slab)
        result = SlabCache(slab["slab_cache"])
        assert result.name  # make sure the result is sane
        return base, result
    except Exception:
        pass
    return None, None


#########################################
# structurs relevant to slab
#
#########################################


def kmem_cache_node_pad_sz(val: int) -> int | None:
    ptrsize = pwndbg.aglib.arch.ptrsize
    for j in range(8):
        nr_partial = pwndbg.aglib.memory.u32(val)
        next = pwndbg.aglib.memory.read_pointer_width(val + ptrsize)
        prev = pwndbg.aglib.memory.read_pointer_width(val + ptrsize * 2)
        val += ptrsize
        if (
            nr_partial < 0x20
            and pwndbg.aglib.memory.is_kernel(next)
            and pwndbg.aglib.memory.is_kernel(prev)
        ):
            return j * ptrsize
    return None


def get_kmem_cache():
    slab_caches = kernel.slab_caches()
    assert slab_caches, "can't find slab_caches"
    return int(slab_caches["prev"]) & ~0xFF


def kmem_cache_pad_sz() -> tuple[int, int]:
    # find the distance between the first kmem_cache's name and its first node cache
    # the name for the first kmem_cache (most likely) has the name "kmem_cache"
    # and the global var is also named "kmem_cache"
    kconfig = kernel.kconfig()
    name = "kmem_cache"
    name_off = None
    ptrsize = pwndbg.aglib.arch.ptrsize
    kmem_cache = get_kmem_cache()
    for i in range(0x20):
        val = pwndbg.aglib.memory.read_pointer_width(kmem_cache + i * ptrsize)
        if pwndbg.aglib.memory.string(val) == name.encode():
            name_off = i * ptrsize
            break
    assert name_off, "can't determine kmem_cache name offset"
    distance, node_cache_pad = None, None
    krelease = kernel.krelease()
    kasan_config_name = (
        "CONFIG_KASAN_GENERIC" if not krelease or krelease >= (6, 3) else "CONFIG_KASAN"
    )
    if (not krelease or krelease >= (6, 2)) and all(
        config not in kconfig for config in ("CONFIG_HARDENED_USERCOPY", kasan_config_name)
    ):
        if all(
            config not in kconfig
            for config in ("CONFIG_SYSFS", "CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_NUMA")
        ):
            node_cache_pad = kmem_cache_node_pad_sz(
                kmem_cache + name_off + ptrsize * 3
            )  # name ptr + 2 list ptrs
            assert node_cache_pad, "can't find kmem_cache node"
            distance = ptrsize if "CONFIG_SLAB_FREELIST_RANDOM" in kconfig else 0
            return distance, node_cache_pad
        if "CONFIG_SLAB_FREELIST_RANDOM" in kconfig:
            for i in range(3, 0x20):
                ptr = kmem_cache + name_off + i * ptrsize
                val = pwndbg.aglib.memory.read_pointer_width(ptr)
                if pwndbg.aglib.memory.is_kernel(val) and all(
                    pwndbg.aglib.memory.uint(val + i * 4) < 0x10000 for i in range(10)
                ):  # checks the random_seq ptr for kmem_cache cache
                    _distance = (i + 1) * ptrsize
                    val = pwndbg.aglib.memory.read_pointer_width(kmem_cache + name_off + _distance)
                    node_cache_pad = kmem_cache_node_pad_sz(val)
                    if node_cache_pad is not None:
                        distance = _distance
                        break
            assert distance, "can't find kmem_cache node"
    if distance is None:
        for i in range(3, 0x20):
            ptr = kmem_cache + name_off + i * ptrsize
            val = pwndbg.aglib.memory.read_pointer_width(ptr - ptrsize)
            if pwndbg.aglib.memory.peek(val) is not None:
                continue
            val = pwndbg.aglib.memory.read_pointer_width(ptr)
            if pwndbg.aglib.memory.peek(val) is None:
                continue
            node_cache_pad = kmem_cache_node_pad_sz(val)
            if node_cache_pad is not None:
                distance = i * ptrsize
                break
    assert distance is not None and node_cache_pad is not None, "can't find kmem_cache node"
    distance -= ptrsize * 3  # the name ptr + list_head
    for config in ("CONFIG_SLAB_FREELIST_HARDENED", "CONFIG_NUMA", "CONFIG_SLAB_FREELIST_RANDOM"):
        if config in kconfig:
            distance -= ptrsize
    if kasan_config_name in kconfig and krelease:  # kasan
        if krelease >= (6, 3) or krelease < (6, 1) or "CONFIG_KASAN_GENERIC" in kernel.kconfig():
            distance -= pwndbg.aglib.typeinfo.uint.sizeof * 2
        if (5, 12) <= krelease < (6, 3):
            distance -= ptrsize
    if "CONFIG_HARDENED_USERCOPY" in kconfig or (krelease and krelease < (6, 2)):
        distance -= pwndbg.aglib.typeinfo.uint.sizeof * 2
    assert distance < 0x1000, "cannot find kmem_cache padding size"
    return distance, node_cache_pad


def get_kmem_cache_padding_sz() -> int:
    ptrsize = pwndbg.aglib.arch.ptrsize
    off = ptrsize  # __page_flags
    if "CONFIG_SLAB_VIRTUAL" in kernel.kconfig():
        off = None
        # per cpu cache always exists because CONFIG_SLAB_VIRTUAL -> !CONFIG_SLUB_TINY
        kmem_cache_addr = get_kmem_cache()
        kmem_cache_cpu = pwndbg.aglib.memory.read_pointer_width(kmem_cache_addr)
        slabs = []
        for i in range(pwndbg.aglib.kernel.nproc()):
            _cache_cpu = int(pwndbg.aglib.kernel.per_cpu(kmem_cache_cpu, i))
            ptr = pwndbg.aglib.memory.read_pointer_width(
                _cache_cpu + ptrsize * 2
            )  # struct slab *slab
            if pwndbg.aglib.memory.is_kernel(ptr):
                slabs.append(ptr)
            if "CONFIG_SLUB_CPU_PARTIAL" in kernel.kconfig():
                ptr = pwndbg.aglib.memory.read_pointer_width(_cache_cpu + ptrsize * 3)  # partial
                if pwndbg.aglib.memory.is_kernel(ptr):
                    slabs.append(ptr)
        for slab in slabs:
            for i in range(1, 0x10):  # skip the first slab ptr, find the ptr to kmem_cache
                # find kmem_cache ptr which should be in slab virtual range (allocated with SLUB)
                addr = slab + i * ptrsize
                if not pwndbg.aglib.memory.is_kernel(addr):
                    continue
                val = pwndbg.aglib.memory.read_pointer_width(addr)
                if kernel.slab_virtual() < val and pwndbg.aglib.memory.is_kernel(val):
                    off = ptrsize * i
                    break
            if off is not None:
                break
        if off is None:
            off = 7 * ptrsize  # default value for mitigation-6.12
    return off


def kmem_cache_structs(node_cache_pad: int) -> str:
    if pwndbg.aglib.kernel.symbol.kversion_cint() is None:
        return ""
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
    result += f"#define PADDING {get_kmem_cache_padding_sz()}\n"
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
        char pad[PADDING];
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
#ifndef CONFIG_SLAB_VIRTUAL
        unsigned int __page_type;
        atomic_t __page_refcount;
#endif
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
    if "CONFIG_SLAB_VIRTUAL" in kernel.kconfig():
        # TODO: the size of freed_slabs_lock is inaccurate but I'm not sure how to handle it
        result += """
        struct kmem_cache_virtual {
            int freed_slabs_lock; // spinlock_t -> this struct is complex cuz its config dep
            struct list_head freed_slabs;
            struct list_head freed_slabs_min;
            unsigned long nr_freed_pages;
        };
        """
    return result


@pwndbg.aglib.kernel.typeinfo_recovery("struct kmem_cache", requires_kversion=True)
def recover_slab_typeinfo() -> str:
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
        "CONFIG_LOCKDEP",
        "CONFIG_SLAB_VIRTUAL",
    )
    for config in configs:
        if config in kconfig:
            defs.append(config)
    sz, node_cache_pad = kmem_cache_pad_sz()
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
#if KVERSION >= KERNEL_VERSION(6, 18, 0)
#if !defined(CONFIG_SLUB_TINY) && defined(CONFIG_LOCKDEP)
        char lock_key[POINTER_SIZE * 2]; // sizeof(hash_entry)
#endif
        void *cpu_sheaves;
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
#if KVERSION >= KERNEL_VERSION(6, 18, 0)
        unsigned int sheaf_capacity;
#endif
        struct kmem_cache_order_objects oo;
        /* Allocation and freeing of slabs */
        struct kmem_cache_order_objects min;
#if KVERSION < KERNEL_VERSION(5, 19, 0)
        struct kmem_cache_order_objects max;
#endif
#ifdef CONFIG_SLAB_VIRTUAL
        struct kmem_cache_virtual virtual;
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
        struct kmem_cache_node *node[{kernel.num_numa_nodes()}];
    }};
    """
    return result
