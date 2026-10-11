from __future__ import annotations

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.search
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.lib.memory import Page
from pwndbg.lib.regs import BitFlags

from ..paging import BIT
from ..paging import PageTableLevel
from ..paging import PagewalkResult
from ..paging import Paging
from ..paging import first_kernel_page_start


class x86_64Paging(Paging):
    def __init__(self) -> None:
        self.P4D_SHIFT = 39

    def phys_to_virt(self, phys: int) -> int:
        return pwndbg.aglib.arch.unsigned(phys + self.physmap)

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    def virt_to_phys(self, virt: int) -> int:
        _virt: int | None = virt
        if not (pwndbg.aglib.memory.is_kernel(virt) and virt < self.vmalloc):
            # if not within physmap range, first find the physmap address
            _virt = self.pagewalk(virt).virt
        if _virt is None:
            _virt = virt
        return _virt - self.physmap

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.vmemmap

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.vmemmap) >> self.STRUCT_PAGE_SHIFT

    @property
    def enabled(self) -> bool:
        return int(pwndbg.aglib.regs.read_reg("cr0")) & BIT(31) != 0

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pagetable_level_names(self) -> tuple[str, ...]:
        # https://blog.zolutal.io/understanding-paging/
        match self.paging_level:
            case 4:
                return ("Page", "PT", "PMD", "PUD", "PGD")
            case 5:
                return ("Page", "PT", "PMD", "P4D", "PUD", "PGD")
        return ()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def va_bits(self) -> int:
        return 48 if self.paging_level == 4 else 51

    @pwndbg.lib.cache.cache_until("stop")
    def get_vmalloc_vmemmap_bases(self) -> tuple[int | None, int | None]:
        result = None
        try:
            target = self.physmap.to_bytes(8, byteorder="little")
            mapping = pwndbg.aglib.kernel.first_kernel_ro_page()
            if not mapping:
                return None, None
            result = next(
                pwndbg.aglib.search.search(
                    target, mappings=[mapping], aligned=pwndbg.aglib.arch.ptrsize
                ),
                None,
            )
        except Exception as e:
            print(e)
        vmemmap, vmalloc = None, None
        if result is not None:
            vmemmap = pwndbg.aglib.memory.u64(result - 0x10)
            vmalloc = pwndbg.aglib.memory.u64(result - 0x8)
        return vmalloc, vmemmap

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap(self) -> int:
        result: int | None = pwndbg.aglib.kernel.try_usymbol("page_offset_base")
        if not result:
            result = first_kernel_page_start()
        return result

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self) -> int | None:
        idt_entries = pwndbg.aglib.kernel.get_idt_entries()
        try:
            entry = next(idt_entries)
            return self._kbase(entry.offset)
        except StopIteration:
            return None

    @property
    def page_shift(self) -> int:
        return 12

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmalloc(self) -> int:
        result: int | None = pwndbg.aglib.kernel.try_usymbol("vmalloc_base")
        if result is not None:
            return result
        result, _ = self.get_vmalloc_vmemmap_bases()
        if result is not None:
            return result
        # resort to default
        return 0xFF91000000000000 if self.paging_level == 5 else 0xFFFFC88000000000

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmemmap(self) -> int:
        result: int | None = pwndbg.aglib.kernel.try_usymbol("vmemmap_base")
        if result is not None:
            return result
        _, result = self.get_vmalloc_vmemmap_bases()
        if result is not None:
            return result
        # resort to default
        return 0xFFD4000000000000 if self.paging_level == 5 else 0xFFFFEA0000000000

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def slab_virtual(self) -> int:
        return pwndbg.aglib.arch.unsigned(-3, self.P4D_SHIFT)

    @property
    def SLAB_DATA_BASE_ADDR(self) -> int:
        STRUCT_SLAB_SIZE = 32 * pwndbg.aglib.arch.ptrsize
        SLAB_VPAGES = (1 << self.P4D_SHIFT) // self.page_size
        SLAB_META_SIZE = pwndbg.lib.memory.round_up(STRUCT_SLAB_SIZE * SLAB_VPAGES, self.page_size)
        return self.slab_virtual + SLAB_META_SIZE

    def slab_to_virt(self, slab: int) -> int:
        a = pwndbg.aglib.typeinfo.load("struct slab")
        # default is true for mitigation-6.12
        # TODO: use heuristics to derive the size of the struct
        slab_size = (14 * pwndbg.aglib.arch.ptrsize) if not a else a.sizeof
        idx = (slab - self.slab_virtual) // slab_size
        return self.SLAB_DATA_BASE_ADDR + self.page_size * idx

    def virt_to_slab(self, virt: int) -> int:
        a = pwndbg.aglib.typeinfo.load("struct slab")
        # default is true for mitigation-6.12
        slab_size = (14 * pwndbg.aglib.arch.ptrsize) if not a else a.sizeof
        slab = self.slab_virtual + (virt - self.SLAB_DATA_BASE_ADDR) // self.page_size * slab_size
        slab = pwndbg.aglib.memory.get_typed_pointer("struct slab", slab)
        return int(slab["compound_slab_head"])

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def paging_level(self) -> int:
        cr4 = pwndbg.aglib.regs.read_reg("cr4")
        return 4 if cr4 is None or (cr4 & (1 << 12)) == 0 else 5

    @pwndbg.lib.cache.cache_until("stop")
    def markers(self) -> tuple[tuple[str | None, int | None], ...]:
        # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
            ("ldt remap", 0xFFFF880000000000 if self.paging_level == 4 else 0xFF10000000000000),
            (self.PHYSMAP, self.physmap),
            (self.VMALLOC, self.vmalloc),
            (self.VMEMMAP, self.vmemmap),
            ("cpu entry", 0xFFFFFE0000000000),
            ("slab virtual", self.slab_virtual),
            (None, self.slab_virtual + (1 << self.P4D_SHIFT)),
            (self.ESPSTACK, 0xFFFFFF0000000000),
            ("EFI", 0xFFFFFFEF00000000),
            (self.KERNELLAND, self.kbase),
            ("fixmap", 0xFFFFFFFFFF000000),
            ("legacy abi", 0xFFFFFFFFFF600000),
            (None, 0xFFFFFFFFFFFFFFFF),
        )

    def adjust(self, name: str) -> str:
        name = name.lower()
        if "low kernel" in name:
            return self.PHYSMAP
        if "high kernel" in name:
            return self.KERNELLAND
        if self.VMALLOC in name:
            return self.VMALLOC
        if self.VMEMMAP in name:
            return self.VMEMMAP
        if " area" in name:
            return name[:-5]
        return name

    def handle_kernel_pages(self, pages: tuple[Page, ...]) -> None:
        kernel_idx = None
        kbase = self.kbase
        stack = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack)
        for i, page in enumerate(pages):
            if kernel_idx is None and kbase is not None and kbase in page:
                kernel_idx = i
                break
        if kernel_idx is None:
            return
        has_loadable_driver = False
        for i in range(kernel_idx, len(pages)):
            page = pages[i]
            if page.objfile != self.KERNELLAND:
                break
            if page.start == kbase:
                continue
            # the first executable page after kernel text is the start of bpf/loadable driver
            if has_loadable_driver or page.execute:
                page.objfile = self.KERNELDRIVER
                has_loadable_driver = True
                continue
            if not page.execute:
                if page.write:
                    page.objfile = self.KERNELBSS
                else:
                    page.objfile = self.KERNELRO
        if not stack:
            return
        for page in pages:
            if stack in page:
                page.objfile += " [stack]"

    @pwndbg.lib.cache.cache_until("stop")
    def pagewalk(self, target: int, entry: int | None = None, virt: bool = True) -> PagewalkResult:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        if entry is None:
            return PagewalkResult()
        return self._pagewalk(target, entry, virt)

    @pwndbg.lib.cache.cache_until("stop")
    def pagescan(self, entry: int | None = None) -> tuple[Page, ...]:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        if entry is None:
            return ()
        return tuple(self._pagescan(entry))

    def bitflags(self, level: PageTableLevel) -> BitFlags:
        return BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("U", 2), ("W", 1), ("P", 0)])

    def should_stop_pagewalk(self, entry: int) -> bool:
        return entry & (1 << 7) > 0
