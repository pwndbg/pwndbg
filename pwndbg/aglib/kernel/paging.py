from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Dict
from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.lib.regs
from pwndbg.aglib.kernel.vmmap import kernel_vmmap_pages
from pwndbg.lib.regs import BitFlags

# don't return None but rather an invalid value for address markers
# this way arithmetic ops do not panic if physmap is not found
INVALID_ADDR = 1 << 64


@pwndbg.lib.cache.cache_until("stop")
def first_kernel_page_start():
    for page in kernel_vmmap_pages():
        if page.start and pwndbg.aglib.memory.is_kernel(page.start):
            return page.start
    return INVALID_ADDR


@dataclass
class PageTableLevel:
    name: str
    entry: int
    virt: int  # within physmap
    idx: int


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

    addr_marker_sz: int
    va_bits: int
    pagetable_cache: Dict[pwndbg.dbg_mod.Value, Dict[int, int]] = {}
    pagetableptr_cache: Dict[int, pwndbg.dbg_mod.Value] = {}
    pagetable_level_names: Tuple[str, ...]

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SIZE(self):
        a = pwndbg.aglib.typeinfo.load("struct page")
        if a is None:
            # true with the most common set of configurations
            # this struct should always present if a vmlinux is added
            return 0x40
        # needs to be rounded up to a power of 2 (consider the layout of vmemmap)
        return 1 << math.ceil(math.log2(a.sizeof))

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SHIFT(self):
        return int(math.log2(self.STRUCT_PAGE_SIZE))

    @property
    def physmap(self) -> int:
        raise NotImplementedError()

    @property
    def vmalloc(self) -> int:
        raise NotImplementedError()

    @property
    def vmemmap(self) -> int:
        raise NotImplementedError()

    @property
    def kbase(self) -> int:
        raise NotImplementedError()

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
        if address is None:
            return None
        for mapping in kernel_vmmap_pages():
            # should be page aligned -- either from pt-dump or info mem

            # only search in kernel mappings:
            # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
            if not pwndbg.aglib.memory.is_kernel(mapping.vaddr):
                continue

            if address in mapping:
                return mapping.vaddr

        return None

    def pagewalk(self, target, entry) -> Tuple[PageTableLevel, ...]:
        raise NotImplementedError()

    def pagewalk_helper(self, target, entry) -> Tuple[PageTableLevel, ...]:
        base = self.physmap
        if entry > base:
            # user inputted a physmap address as pointer to pgd
            entry -= base
        level = self.paging_level
        result = [PageTableLevel(None, None, None, None)] * (level + 1)
        page_shift = self.page_shift
        ENTRYMASK = ~((1 << page_shift) - 1) & ((1 << self.va_bits) - 1)
        IDXMASK = (1 << (page_shift - math.ceil(math.log2(pwndbg.aglib.arch.ptrsize)))) - 1
        for i in range(level, 0, -1):
            vaddr = (entry & ENTRYMASK) + base - self.phys_offset
            if self.should_stop_pagewalk(entry):
                break
            shift = (i - 1) * (page_shift - 3) + page_shift
            offset = target & ((1 << shift) - 1)
            idx = (target & (IDXMASK << shift)) >> shift
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
                return tuple(result)
            result[i] = PageTableLevel(self.pagetable_level_names[i], entry, vaddr, idx)
        result[0] = PageTableLevel(
            self.pagetable_level_names[0],
            entry,
            (entry & ENTRYMASK) + base + offset - self.phys_offset,
            None,
        )
        return tuple(result)

    def pageentry_flags(self, level) -> BitFlags:
        raise NotImplementedError()

    def should_stop_pagewalk(self, is_last):
        raise NotImplementedError()

    @property
    def phys_offset(self):
        return 0


class x86_64PagingInfo(ArchPagingInfo):
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
            result = next(
                pwndbg.search.search(target, mappings=[mapping], aligned=pwndbg.aglib.arch.ptrsize),
                None,
            )
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
            result = first_kernel_page_start()
        return result

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self):
        idt_entries = pwndbg.aglib.kernel.get_idt_entries()
        if len(idt_entries) == 0:
            return None
        return self.kbase_helper(idt_entries[0].offset)

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
        return 4 if (pwndbg.aglib.regs.read_reg("cr4") & (1 << 12)) == 0 else 5

    @pwndbg.lib.cache.cache_until("stop")
    def markers(self) -> Tuple[Tuple[str, int], ...]:
        # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
            ("ldt remap", 0xFFFF880000000000 if self.paging_level == 4 else 0xFF10000000000000),
            (self.PHYSMAP, self.physmap),
            (self.VMALLOC, self.vmalloc),
            (self.VMEMMAP, self.vmemmap),
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
        kbase = self.kbase
        for i, page in enumerate(pages):
            if kernel_idx is None and kbase is not None and kbase in page:
                kernel_idx = i
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
            if pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack) in page:
                page.objfile = "kernel [stack]"

    def pagewalk(self, target, entry) -> Tuple[PageTableLevel, ...]:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        return self.pagewalk_helper(target, entry)

    def pageentry_flags(self, is_last) -> BitFlags:
        return BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("U", 2), ("W", 1), ("P", 0)])

    def should_stop_pagewalk(self, entry):
        return entry & (1 << 7) > 0


class Aarch64PagingInfo(ArchPagingInfo):
    def __init__(self):
        self.tcr_el1 = pwndbg.lib.regs.aarch64_tcr_flags
        self.tcr_el1.value = pwndbg.aglib.regs.TCR_EL1
        id_aa64mmfr2_el1 = pwndbg.lib.regs.aarch64_mmfr_flags
        id_aa64mmfr2_el1.value = pwndbg.aglib.regs.ID_AA64MMFR2_EL1
        feat_lva = id_aa64mmfr2_el1.value is not None and id_aa64mmfr2_el1["VARange"] == 0b0001
        self.va_bits = 64 - self.tcr_el1["T1SZ"]  # this is prob only `vabits_actual`
        self.PAGE_OFFSET = self._PAGE_OFFSET(self.va_bits)  # physmap base address without KASLR
        if feat_lva:
            self.va_bits = min(52, self.va_bits)
        self.va_bits_min = 48 if self.va_bits > 48 else self.va_bits
        self._vmalloc = self._PAGE_END(
            self.va_bits_min
        )  # also includes KASAN and kernel module regions
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
    def vmalloc(self) -> int:
        return self._vmalloc

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap(self):
        return first_kernel_page_start()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self):
        return self.kbase_helper(pwndbg.aglib.regs.vbar)

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kversion(self):
        return pwndbg.aglib.kernel.krelease()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def module_start(self):
        if self.kbase is None:
            return None
        res = None
        for page in kernel_vmmap_pages()[::-1]:
            if page.start >= self.kbase:
                continue
            if page.start < self.vmalloc:
                break
            if page.execute:
                res = page.start
                break
        return res

    def _PAGE_OFFSET(self, va):  # aka PAGE_START
        return (-(1 << va)) & 0xFFFFFFFFFFFFFFFF

    def _PAGE_END(self, va):
        return (-(1 << (va - 1))) & 0xFFFFFFFFFFFFFFFF

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmemmap(self):
        if self.kversion is None:
            return INVALID_ADDR
        vmemmap_shift = self.page_shift - self.STRUCT_PAGE_SHIFT
        if self.kversion < (5, 4):
            self.VMEMMAP_SIZE = 1 << (self.va_bits - self.page_shift - 1 + self.STRUCT_PAGE_SHIFT)
            self.VMEMMAP_START = self.PAGE_OFFSET - self.VMEMMAP_SIZE
        elif self.kversion < (5, 11):
            self.VMEMMAP_SIZE = (
                self._PAGE_END(self.va_bits_min) - self.PAGE_OFFSET
            ) >> vmemmap_shift
            self.VMEMMAP_START = (-self.VMEMMAP_SIZE - 0x00200000) & 0xFFFFFFFFFFFFFFFF
        elif self.kversion < (6, 9):
            self.VMEMMAP_SIZE = (
                self._PAGE_END(self.va_bits_min) - self.PAGE_OFFSET
            ) >> vmemmap_shift
            self.VMEMMAP_START = self._PAGE_OFFSET(self.va_bits - vmemmap_shift)
        else:
            VMEMMAP_RANGE = self._PAGE_END(self.va_bits_min) - self.PAGE_OFFSET
            self.VMEMMAP_SIZE = (VMEMMAP_RANGE >> self.page_shift) * self.STRUCT_PAGE_SIZE
            self.VMEMMAP_START = (-0x40000000 - self.VMEMMAP_SIZE) & 0xFFFFFFFFFFFFFFFF

        # obtained through debugging -- kaslr offset of physmap determines the offset of vmemmap
        vmemmap_kaslr = (self.physmap - self.PAGE_OFFSET - self.phys_offset) >> vmemmap_shift
        return self.VMEMMAP_START + vmemmap_kaslr

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pci(self):
        if self.kversion is None:
            return None
        self.pci_end = INVALID_ADDR
        if self.kversion >= (6, 9):
            pci = self.VMEMMAP_START + self.VMEMMAP_SIZE + 0x00800000  # 8M
            self.pci_end = pci + 0x01000000  # 16M
            return pci
        if self.kversion >= (5, 11):
            self.pci_end = self.VMEMMAP_START - 0x00800000  # 8M
        else:
            self.pci_end = self.VMEMMAP_START - 0x00200000  # 2M
        return self.pci_end - 0x01000000  # 16M

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def fixmap(self):
        if self.kversion is None:
            return INVALID_ADDR
        if self.kversion < (5, 11):
            FIXADDR_TOP = self.pci - 0x00200000  # 2M
        elif self.kversion < (6, 9):
            FIXADDR_TOP = self.VMEMMAP_START - 0x02000000  # 32M
        else:
            FIXADDR_TOP = (-0x00800000) & 0xFFFFFFFFFFFFFFFF
        # https://elixir.bootlin.com/linux/v6.16.5/source/arch/arm64/include/asm/fixmap.h#L102
        # 0x1000 is an upper estimate
        FIXADDR_SIZE = 0x1000 << self.page_shift
        return FIXADDR_TOP - FIXADDR_SIZE

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
    @pwndbg.lib.cache.cache_until("objfile")
    def page_shift_heuristic(self) -> int:
        sym = pwndbg.aglib.symbol.lookup_symbol_addr("copy_page_to_iter")
        if sym is not None:
            pattern = re.compile(r"mov.*(0x1000|0x10000|0x4000)")
            for inst in pwndbg.aglib.nearpc.nearpc(int(sym), lines=50):
                if (result := pattern.search(inst)) is not None:
                    return int(math.log2(int(result.group(1), 16)))
        return 12  # default

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def page_shift(self) -> int:
        match self.tcr_el1["TG1"]:
            case 0b01:
                return 14
            case 0b10:
                return 12
            case 0b11:
                return 16
        return self.page_shift_heuristic

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def page_shift_user(self) -> int:
        match self.tcr_el1["TG0"]:
            case 0b00:
                return 12
            case 0b01:
                return 16
            case 0b10:
                return 14
        return self.page_shift_heuristic

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
        vmalloc_end = None
        if self.vmemmap and self.pci and self.fixmap:
            vmalloc_end = min(self.vmemmap, self.pci, self.fixmap)
        return (
            (self.USERLAND, 0),
            (None, self.PAGE_OFFSET),
            (self.PHYSMAP, self.physmap),
            (None, self.vmalloc),
            (self.VMALLOC, self.vmalloc),
            (None, vmalloc_end),
            (self.VMEMMAP, self.vmemmap),
            (None, self.VMEMMAP_START + self.VMEMMAP_SIZE),
            ("pci", self.pci),
            (None, self.pci_end),
            ("fixmap", self.fixmap),
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
        if self.kbase is None:
            return
        for i in range(len(pages)):
            page = pages[i]
            if page.start > self.kbase + self.ksize:
                continue
            if self.module_start and self.module_start <= page.start < self.kbase:
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
            if pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack) in page:
                page.objfile = "kernel [stack]"

    @property
    @pwndbg.lib.cache.cache_until("start")
    def phys_offset(self):
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

    def pagewalk(self, target, entry) -> Tuple[PageTableLevel, ...]:
        if entry is None:
            if pwndbg.aglib.memory.is_kernel(target):
                entry = pwndbg.aglib.regs.TTBR1_EL1
            else:
                entry = pwndbg.aglib.regs.TTBR0_EL1
        self.entry = entry
        return self.pagewalk_helper(target, entry)

    def pageentry_flags(self, is_last) -> BitFlags:
        if is_last:
            return BitFlags([("UNX", 54), ("PNX", 53), ("AP", (6, 7))])
        return BitFlags([("UNX", 60), ("PNX", 59), ("AP", (6, 7))])

    def should_stop_pagewalk(self, entry):
        # self.entry is set because the call chain
        return (((entry & 1) == 0) or ((entry & 3) == 1)) and entry != self.entry
