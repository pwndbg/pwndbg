from __future__ import annotations

from typing import Generator
from typing import List
from typing import Set

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
from pwndbg.aglib import kernel
from pwndbg.aglib.kernel.macros import compound_head
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.aglib.kernel.macros import swab


def caches() -> Generator[SlabCache, None, None]:
    slab_caches = pwndbg.aglib.symbol.lookup_symbol("slab_caches")
    if slab_caches is None:
        # Symbol not found
        return

    slab_caches = slab_caches.dereference()
    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        yield SlabCache(slab_cache)


def get_cache(target_name: str) -> SlabCache | None:
    slab_caches = pwndbg.aglib.symbol.lookup_symbol("slab_caches")
    if slab_caches is None:
        # Symbol not found
        return None

    slab_caches = slab_caches.dereference()
    for slab_cache in for_each_entry(slab_caches, "struct kmem_cache", "list"):
        if target_name == slab_cache["name"].string():
            return SlabCache(slab_cache)
    return None


def slab_struct_type() -> str:
    # In Linux kernel version 5.17 a slab struct was introduced instead of the previous page struct
    if pwndbg.aglib.typeinfo.load("struct slab") is not None:
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
        current_object = self.start_addr
        while current_object:
            addr = int(current_object)
            yield current_object
            current_object = pwndbg.aglib.memory.pvoid(addr + self.offset)
            if self.random:
                current_object ^= self.random ^ swab(addr + self.offset)

    def __int__(self) -> int:
        return self.start_addr

    def __len__(self) -> int:
        return sum(1 for _ in self)

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
        if not kernel.kconfig():
            try:
                return int(self._slab_cache["random"])
            except pwndbg.dbg_mod.Error:
                return 0

        return (
            int(self._slab_cache["random"]) if "SLAB_FREELIST_HARDENED" in kernel.kconfig() else 0
        )

    @property
    def size(self) -> int:
        return int(self._slab_cache["size"])

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
    def cpu_cache(self) -> CpuCache:
        """returns cpu cache associated to current thread"""
        cpu = pwndbg.dbg.selected_thread().index() - 1
        cpu_cache = kernel.per_cpu(self._slab_cache["cpu_slab"], cpu=cpu)
        return CpuCache(cpu_cache, self, cpu)

    @property
    def cpu_caches(self) -> Generator[CpuCache, None, None]:
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
        return int(self._slab_cache["cpu_partial"])

    @property
    def inuse(self) -> int:
        return int(self._slab_cache["inuse"])

    @property
    def __oo_x(self) -> int:
        return int(self._slab_cache["oo"]["x"])

    @property
    def oo_order(self):
        return oo_order(self.__oo_x)

    @property
    def oo_objects(self):
        return oo_objects(self.__oo_x)


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
        return Slab(_slab.dereference(), self, self.slab_cache)

    @property
    def partial_slabs(self) -> List[Slab]:
        partial_slabs = []
        cur_slab = self._cpu_cache["partial"]
        cur_slab_int = int(cur_slab)
        while cur_slab_int:
            _slab = cur_slab.dereference()
            partial_slabs.append(Slab(_slab, self, self.slab_cache, is_partial=True))
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
            ret.append(Slab(slab.dereference(), None, self.slab_cache, is_partial=True))
        return ret


class Slab:
    def __init__(
        self,
        slab: pwndbg.dbg_mod.Value,
        cpu_cache: CpuCache | None,
        slab_cache: SlabCache,
        is_partial: bool = False,
    ) -> None:
        self._slab = slab
        self.cpu_cache = cpu_cache
        self.slab_cache = slab_cache
        self.is_partial = is_partial

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
            # `inuse` will always equal `objects` for the active slab, so we
            # need to subtract the length of the freelists
            for freelist in self.freelists:
                inuse -= len(freelist)
        return inuse

    @property
    def slabs(self) -> int:
        return int(self._slab[f"{slab_struct_type()}s"])

    @property
    def pobjects(self) -> int:
        if not self.is_partial:
            return 0
        try:
            return int(self._slab["pobjects"])
        except pwndbg.dbg_mod.Error:
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


def find_containing_slab_cache(addr: int) -> SlabCache | None:
    """Find the slab cache associated with the provided address."""
    min_pfn = 0
    max_pfn = pwndbg.aglib.symbol.lookup_symbol_value("max_pfn")
    assert max_pfn is not None, "Symbol max_pfn not found"

    page_size = kernel.page_size()

    start_addr = kernel.pfn_to_virt(min_pfn)
    end_addr = kernel.pfn_to_virt(max_pfn + page_size)

    if not start_addr <= addr < end_addr:
        # address is out of range
        return None

    page = pwndbg.aglib.memory.get_typed_pointer_value("struct page", kernel.virt_to_page(addr))
    head_page = compound_head(page)

    slab_type = pwndbg.aglib.typeinfo.load(f"struct {slab_struct_type()}")
    assert slab_type is not None, "Symbol slab not found"

    slab = head_page.cast(slab_type)
    return SlabCache(slab["slab_cache"])
