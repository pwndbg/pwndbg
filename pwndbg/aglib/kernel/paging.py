from __future__ import annotations

import math
from typing import Dict
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.lib.regs import BitFlags

# don't return None but rather an invalid value for address markers
# this way arithmetic ops do not panic if physmap is not found
INVALID_ADDR = 1 << 64


@pwndbg.lib.cache.cache_until("stop")
def get_memory_map_raw() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return pwndbg.aglib.kernel.vmmap.kernel_vmmap(False)


@pwndbg.lib.cache.cache_until("stop")
def first_kernel_page_start():
    for page in get_memory_map_raw():
        if page.start and pwndbg.aglib.memory.is_kernel(page.start):
            return page.start
    return INVALID_ADDR


class ArchPagingInfo:
    USERLAND = "userland"
    KERNELLAND = "kernel [.text]"
    KERNELRO = "kernel [.rodata]"
    KERNELBSS = "kernel [.bss]"
    KERNELDRIVER = "kernel [.driver .bpf]"
    ESPSTACK = "espfix"
    PHYSMAP = "physmap"
    VMALLOC = "vmalloc"
    VMEMMAP = "vmemmap"

    physmap: int
    vmalloc: int
    vmemmap: int
    kbase: int
    addr_marker_sz: int
    va_bits: int
    pagetable_cache: Dict[pwndbg.dbg_mod.Value, Dict[int, int]] = {}
    pagetableptr_cache: Dict[int, pwndbg.dbg_mod.Value] = {}

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SIZE(self):
        a = pwndbg.aglib.typeinfo.load("struct page")
        if a is None:
            # this has been the case for all v5 and v6 releases
            return 0x40
        return a.sizeof

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SHIFT(self):
        # needs to be rounded up (consider the layout of vmemmap)
        return math.ceil(math.log2(self.STRUCT_PAGE_SIZE))

    @property
    def page_shift(self) -> int:
        raise NotImplementedError()

    @property
    def paging_level(self) -> int:
        raise NotImplementedError()

    def adjust(self, name: str) -> str:
        raise NotImplementedError()

    def markers(self) -> Tuple[Tuple[str, int], ...]:
        raise NotImplementedError()

    def handle_kernel_pages(self, pages):
        # this is arch dependent
        raise NotImplementedError()

    def kbase_helper(self, address):
        for mapping in get_memory_map_raw():
            # should be page aligned -- either from pt-dump or info mem

            # only search in kernel mappings:
            # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
            if not pwndbg.aglib.memory.is_kernel(mapping.vaddr):
                continue

            if address in mapping:
                return mapping.vaddr

        return None

    def pagewalk(
        self, target, entry
    ) -> Tuple[Tuple[str, ...], List[Tuple[int | None, int | None]]]:
        raise NotImplementedError()

    def pagewalk_helper(
        self, target, entry, kernel_phys_base=0
    ) -> List[Tuple[int | None, int | None]]:
        base = self.physmap
        if entry > base:
            # user inputted a physmap address as pointer to pgd
            entry -= base
        level = self.paging_level
        result: List[Tuple[int | None, int | None]] = [(None, None)] * (level + 1)
        page_shift = self.page_shift
        ENTRYMASK = ~((1 << page_shift) - 1) & ((1 << self.va_bits) - 1)
        for i in range(level, 0, -1):
            vaddr = (entry & ENTRYMASK) + base - kernel_phys_base
            if self.should_stop_pagewalk(entry):
                break
            shift = (i - 1) * (page_shift - 3) + page_shift
            offset = target & ((1 << shift) - 1)
            idx = (target & (0x1FF << shift)) >> shift
            entry = 0
            try:
                # with this optimization, roughly x2 as fast on average
                # especially useful when parsing a large number of pages, e.g. set kernel-vmmap monitor
                if vaddr not in self.pagetableptr_cache:
                    self.pagetableptr_cache[vaddr] = pwndbg.aglib.memory.get_typed_pointer(
                        "unsigned long", vaddr
                    )
                table = self.pagetableptr_cache[vaddr]
                if table not in self.pagetable_cache:
                    self.pagetable_cache[table] = {}
                table_cache = self.pagetable_cache[table]
                if idx not in table_cache:
                    table_cache[idx] = int(table[idx])
                entry = table_cache[idx]
                # Prior to optimization:
                # table = pwndbg.aglib.memory.get_typed_pointer("unsigned long", vaddr)
                # entry = int(table[idx])
            except Exception as e:
                print(M.warn(f"Exception while page walking: {e}"))
                entry = 0
            if entry == 0:
                return result
            result[i] = (entry, vaddr)
        result[0] = (entry, (entry & ENTRYMASK) + base + offset - kernel_phys_base)
        return result

    def pageentry_flags(self, level) -> BitFlags:
        raise NotImplementedError()

    def should_stop_pagewalk(self, is_last):
        raise NotImplementedError()


class x86_64PagingInfo(ArchPagingInfo):
    # constants are taken from https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
    def __init__(self):
        self.va_bits = 48 if self.paging_level == 4 else 51
        # https://blog.zolutal.io/understanding-paging/
        self.pagetable_level_names = (
            (
                "Page",
                "PT",
                "PMD",
                "PUD",
                "PGD",
            )
            if self.paging_level == 4
            else (
                "Page",
                "PT",
                "PMD",
                "P4D",
                "PUD",
                "PGD",
            )
        )

    @pwndbg.lib.cache.cache_until("stop")
    def get_vmalloc_vmemmap_bases(self):
        result = None
        try:
            target = self.physmap.to_bytes(8, byteorder="little")
            mapping = pwndbg.aglib.kernel.first_kernel_ro_page()
            result = next(pwndbg.search.search(target, mappings=[mapping]), None)
        except Exception as e:
            print(e)
            pass
        vmemmap, vmalloc = None, None
        if result is not None:
            vmemmap = pwndbg.aglib.memory.u64(result - 0x10)
            vmalloc = pwndbg.aglib.memory.u64(result - 0x8)
        return vmalloc, vmemmap

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap(self):
        result = pwndbg.aglib.kernel.symbol.try_usymbol("page_offset_base")
        if result is None:
            result = INVALID_ADDR
            min = 0xFFFF888000000000 if self.paging_level == 4 else 0xFF11000000000000
            for page in get_memory_map_raw():
                if page.start and page.start >= min:
                    result = page.start
                    break
        return result

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self):
        return self.kbase_helper(pwndbg.aglib.kernel.get_idt_entries()[0].offset)

    @property
    def page_shift(self) -> int:
        return 12

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmalloc(self):
        result = pwndbg.aglib.kernel.symbol.try_usymbol("vmalloc_base")
        if result is not None:
            return result
        result, _ = self.get_vmalloc_vmemmap_bases()
        if result is not None:
            return result
        # resort to default
        return 0xFF91000000000000 if self.paging_level == 5 else 0xFFFFC88000000000

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmemmap(self):
        result = pwndbg.aglib.kernel.symbol.try_usymbol("vmemmap_base")
        if result is not None:
            return result
        _, result = self.get_vmalloc_vmemmap_bases()
        if result is not None:
            return result
        # resort to default
        return 0xFFD4000000000000 if self.paging_level == 5 else 0xFFFFEA0000000000

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def paging_level(self) -> int:
        # CONFIG_X86_5LEVEL is only a hint -- whether 5lvl paging is used depends on the hardware
        # see also: https://www.kernel.org/doc/html/next/x86/x86_64/mm.html
        if first_kernel_page_start() < (0xFFF << (4 * 13)):
            return 5
        return 4

    @pwndbg.lib.cache.cache_until("stop")
    def markers(self) -> Tuple[Tuple[str, int], ...]:
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
            ("ldt remap", 0xFFFF880000000000 if self.paging_level == 4 else 0xFF10000000000000),
            (self.PHYSMAP, self.physmap),
            (self.VMALLOC, self.vmalloc),
            (self.VMEMMAP, self.vmemmap),
            # TODO: find better ways to handle the following constants
            #   I cound not find kernel symbols that reference their values
            #   the actual region base may differ but the region always falls within the below range
            #   even if KASLR is enabled
            ("cpu entry", 0xFFFFFE0000000000),
            (self.ESPSTACK, 0xFFFFFF0000000000),
            ("EFI", 0xFFFFFFEF00000000),
            (self.KERNELLAND, self.kbase),
            ("fixmap", 0xFFFFFFFFFF000000),
            ("legacy abi", 0xFFFFFFFFFF600000),
            (None, 0xFFFFFFFFFFFFFFFF),
        )

    def adjust(self, name):
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

    def handle_kernel_pages(self, pages):
        kernel_idx = None
        for i, page in enumerate(pages):
            if kernel_idx is None and self.kbase in page:
                kernel_idx = i
        kbase = self.kbase
        if kernel_idx is None:
            return
        has_loadable_driver = False
        for i in range(kernel_idx, len(pages)):
            page = pages[i]
            if page.objfile != self.KERNELLAND:
                break
            if not page.execute:
                if page.write:
                    page.objfile = self.KERNELBSS
                else:
                    page.objfile = self.KERNELRO
            if has_loadable_driver:
                page.objfile = self.KERNELDRIVER
            if page.execute and page.start != kbase:
                page.objfile = self.KERNELDRIVER
                has_loadable_driver = True
            if pwndbg.aglib.regs[pwndbg.aglib.regs.stack] in page:
                page.objfile = "kernel [stack]"

    def pagewalk(
        self, target, entry
    ) -> Tuple[Tuple[str, ...], List[Tuple[int | None, int | None]]]:
        if entry is None:
            entry = pwndbg.aglib.regs["cr3"]
        return self.pagetable_level_names, self.pagewalk_helper(target, entry)

    def pageentry_flags(self, is_last) -> BitFlags:
        return BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("U", 2), ("W", 1), ("P", 0)])

    def should_stop_pagewalk(self, entry):
        return entry & (1 << 7) > 0


class Aarch64PagingInfo(ArchPagingInfo):
    def __init__(self):
        self.tcr_el1 = pwndbg.lib.regs.aarch64_tcr_flags
        self.tcr_el1.value = pwndbg.aglib.regs.TCR_EL1
        # TODO: this is probably not entirely correct
        # https://elixir.bootlin.com/linux/v6.16-rc2/source/arch/arm64/include/asm/memory.h#L56
        self.va_bits = 64 - self.tcr_el1["T1SZ"]  # this is prob only `vabits_actual`
        self.va_bits_min = 48 if self.va_bits > 48 else self.va_bits
        # https://elixir.bootlin.com/linux/v6.13.12/source/arch/arm64/include/asm/memory.h#L47
        module_start_wo_kaslr = (-1 << (self.va_bits_min - 1)) + 2**64
        self.vmalloc = module_start_wo_kaslr + 0x80000000
        shift = self.page_shift - self.STRUCT_PAGE_SHIFT
        self.VMEMMAP_SIZE = (module_start_wo_kaslr - ((-1 << self.va_bits) + 2**64)) >> shift
        # correct for linux
        if self.paging_level == 4:
            self.pagetable_level_names = (
                "Page",
                "L3",
                "L2",
                "L1",
                "L0",
            )
        elif self.paging_level == 3:
            self.pagetable_level_names = (
                "Page",
                "L3",
                "L2",
                "L1",
            )

        elif self.paging_level == 2:
            self.pagetable_level_names = (
                "Page",
                "L3",
                "L2",
            )

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap(self):
        # addr = pwndbg.aglib.symbol.lookup_symbol_addr("memstart_addr")
        # if addr is None:
        #     return first_kernel_page_start()
        # return pwndbg.aglib.memory.u(addr)
        return first_kernel_page_start()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self):
        return self.kbase_helper(pwndbg.aglib.regs.vbar)

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kversion(self):
        try:
            return pwndbg.aglib.kernel.krelease()
        except Exception:
            return None

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap_end(self):
        res = None
        for page in get_memory_map_raw():
            if page.end >= self.vmalloc:
                break
            res = page.end
        if res is None:
            return INVALID_ADDR
        return res

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def module_start(self):
        # this is only used for marking the end of module_start
        self.module_end = -1
        res = None
        for page in get_memory_map_raw():
            if page.start >= self.kbase:
                break
            if page.execute:
                res = page.start
        if res is None:
            return INVALID_ADDR
        prev = None
        for page in get_memory_map_raw():
            if page.start >= res:
                if prev is not None and page.start > prev + 0x1000:
                    break
                prev = self.module_end = page.end
        return res

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmemmap(self):
        if self.kversion is None:
            return INVALID_ADDR
        if self.kversion >= (6, 9):
            # https://elixir.bootlin.com/linux/v6.16-rc2/source/arch/arm64/include/asm/memory.h#L33
            result = (-0x40000000 % INVALID_ADDR) - self.VMEMMAP_SIZE
        elif self.kversion >= (5, 11):
            # Linux 5.11 changed the calculation for VMEMMAP_START
            # https://elixir.bootlin.com/linux/v5.11/source/arch/arm64/include/asm/memory.h#L53
            VMEMMAP_SHIFT = self.page_shift - self.STRUCT_PAGE_SHIFT
            result = -(1 << (self.va_bits - VMEMMAP_SHIFT)) % INVALID_ADDR
        else:
            result = (-self.VMEMMAP_SIZE - 2 * 1024 * 1024) + 2**64
        for page in get_memory_map_raw():
            if page.start >= result:
                return page.start
        return INVALID_ADDR

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pci(self):
        if self.kversion is None:
            return None
        self.pci_end = INVALID_ADDR
        if self.kversion >= (6, 9):
            pci = self.vmemmap + self.VMEMMAP_SIZE + 0x00800000
            self.pci_end = pci + 0x01000000
            return pci
        if self.kversion >= (5, 11):
            self.pci_end = self.vmemmap - 0x00800000
            return self.pci_end - 0x01000000
        self.pci_end = self.vmemmap - 0x00200000
        return self.pci_end - 0x01000000

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def ksize(self):
        start = pwndbg.aglib.symbol.lookup_symbol_addr("_text")
        end = pwndbg.aglib.symbol.lookup_symbol_addr("_end")
        if start is not None and end is not None:
            return end - start
        # fallback
        return 100 << 21  # 100M

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def page_shift(self) -> int:
        if self.tcr_el1["TG1"] == 0b01:
            return 14
        elif self.tcr_el1["TG1"] == 0b10:
            return 12
        elif self.tcr_el1["TG1"] == 0b11:
            return 16
        raise NotImplementedError()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def page_shift_user(self) -> int:
        if self.tcr_el1["TG0"] == 0b00:
            return 12
        elif self.tcr_el1["TG0"] == 0b01:
            return 16
        elif self.tcr_el1["TG0"] == 0b10:
            return 14
        raise NotImplementedError()

    @property
    @pwndbg.lib.cache.cache_until("forever")
    def paging_level(self):
        # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
        if self.page_shift == 16:
            return 2
        # in some cases, not all addressing bits are used
        return (self.va_bits - self.page_shift + (self.page_shift - 4)) // (self.page_shift - 3)

    @pwndbg.lib.cache.cache_until("stop")
    def markers(self) -> Tuple[Tuple[str, int], ...]:
        address_markers = pwndbg.aglib.symbol.lookup_symbol_addr("address_markers")
        if address_markers is not None:
            sections = [(self.USERLAND, 0)]
            value = 0
            name = None
            for i in range(20):
                value = pwndbg.aglib.memory.u64(address_markers + i * 0x10)
                name_ptr = pwndbg.aglib.memory.u64(address_markers + i * 0x10 + 8)
                name = None
                if name_ptr > 0:
                    name = pwndbg.aglib.memory.string(name_ptr).decode()
                    name = self.adjust(name)
                if value > 0:
                    sections.append((name, value))
                if value == 0xFFFFFFFFFFFFFFFF:
                    break
            return tuple(sections)
        if self.kversion is None:
            return ()
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
            (self.PHYSMAP, self.physmap),
            (None, self.physmap_end),
            (self.VMALLOC, self.vmalloc),
            (self.VMEMMAP, self.vmemmap),
            (None, self.vmemmap + self.VMEMMAP_SIZE),
            ("pci", self.pci),
            (None, self.pci_end),
            # TODO: prob not entirely correct but the computation is too complicated
            ("fixmap", self.pci_end),
            (None, 0xFFFFFFFFFFFFFFFF),
        )

    def adjust(self, name):
        name = name.lower()
        if "end" in name:
            return None
        if "linear" in name:
            return self.PHYSMAP
        if "modules" in name:
            return self.KERNELDRIVER
        if self.VMEMMAP in name:
            return self.VMEMMAP
        if self.VMALLOC in name:
            return self.VMALLOC
        return " ".join(name.strip().split()[:-1])

    def handle_kernel_pages(self, pages):
        for i in range(len(pages)):
            page = pages[i]
            if page.start < self.module_start or page.start > self.kbase + self.ksize:
                continue
            if self.module_start <= page.start < self.module_end:
                page.objfile = self.KERNELDRIVER
                continue
            if page.start < self.kbase:
                continue
            page.objfile = self.KERNELLAND
            if not page.execute:
                if page.write:
                    page.objfile = self.KERNELBSS
                else:
                    page.objfile = self.KERNELRO
            if pwndbg.aglib.regs[pwndbg.aglib.regs.stack] in page:
                page.objfile = "kernel [stack]"

    @property
    @pwndbg.lib.cache.cache_until("start")
    def kernel_phys_start(self):
        found_system = False
        try:
            for line in pwndbg.dbg.selected_inferior().send_monitor("info mtree -f").splitlines():
                line = line.strip()
                if "Root memory region: system" in line:
                    found_system = True
                if found_system:
                    split = line.split("-")
                    if "ram" in line and len(split) > 1:
                        return int(split[0], 16)
        except Exception:
            pass
        return 0x40000000  # default

    def pagewalk(
        self, target, entry
    ) -> Tuple[Tuple[str, ...], List[Tuple[int | None, int | None]]]:
        if entry is None:
            if pwndbg.aglib.memory.is_kernel(target):
                entry = pwndbg.aglib.regs.TTBR1_EL1
            else:
                entry = pwndbg.aglib.regs.TTBR0_EL1
        self.entry = entry
        return self.pagetable_level_names, self.pagewalk_helper(
            target, entry, self.kernel_phys_start
        )

    def pageentry_flags(self, is_last) -> BitFlags:
        if is_last:
            return BitFlags([("UNX", 54), ("PNX", 53), ("AP", (6, 7))])
        return BitFlags([("UNX", 60), ("PNX", 59), ("AP", (6, 7))])

    def should_stop_pagewalk(self, entry):
        # self.entry is set because the call chain
        return (((entry & 1) == 0) or ((entry & 3) == 1)) and entry != self.entry
