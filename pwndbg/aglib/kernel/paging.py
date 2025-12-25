from __future__ import annotations

import math
import re
import struct
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.kernel
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.regs
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.kernel.vmmap import kernel_vmmap_pages
from pwndbg.lib.memory import Page
from pwndbg.lib.regs import BitFlags

# don't return None but rather an invalid value for address markers
# this way arithmetic ops do not panic if physmap is not found
INVALID_ADDR = 1 << 64


@pwndbg.lib.cache.cache_until("stop")
def first_kernel_page_start() -> int:
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


class PageTableScan:
    MAX_SAME_PG_TABLE_ENTRY = 0x10

    # is_kernel is used only for Aarch64
    def __init__(self, pi: ArchPagingInfo, is_kernel: bool) -> None:
        # from ArchPagingInfo:
        self.paging_level = pi.paging_level
        self.PAGE_ENTRY_MASK = pi.PAGE_ENTRY_MASK
        self.PAGE_INDEX_LEN = pi.PAGE_INDEX_LEN
        self.PAGE_INDEX_MASK = pi.PAGE_INDEX_MASK
        self.page_shift = pi.page_shift
        self.pageentry_flags = pi.pageentry_flags
        self.should_stop_pagewalk = pi.should_stop_pagewalk
        # for scanning
        self.result: List[Page] = []
        self.pagesz = 1 << self.page_shift
        self.counters: Dict[int, int] = {}
        self.ptrsize = pwndbg.aglib.arch.ptrsize
        self.inf = pwndbg.dbg.selected_inferior()
        self.fmt = "<" + ("Q" if self.ptrsize == 8 else "I") * (self.pagesz // self.ptrsize)
        self.cache: Dict[int, List[int]] = {}
        # below are info relating to the current page chunks being coalesced
        self.level_idxes = [0] * (self.paging_level + 1)
        self.curr = None
        self.is_kernel = is_kernel
        self.arch = pwndbg.aglib.arch.name

    def scan(self, entry: int, level_remaining: int) -> None:
        # this needs to be EXTREMELY optimized as it is used to display context
        # making as few functions calls or memory reads as possible
        # avoid unnecessary python pointer deferences or repetative computations whenever possible
        # on average takes less than 0.09 seconds to complete for x64 and 0.12 for aarch64
        # around 25% of the time is used to read qemu system memory
        # in comparison, gdb-pt-dump takes ~0.12 for x64 and a few seconds for aarch64
        # --> 25% speed up for x64 and more than 10x speed up for aarch64
        pagesz = self.pagesz
        addr = entry & self.PAGE_ENTRY_MASK
        entries = self.cache.get(addr, None)
        ptrsize: int = pwndbg.aglib.arch.ptrsize
        if not entries:
            self.cache[addr] = entries = struct.unpack(self.fmt, self.inf.read_memory(addr, pagesz))
        for i, entry in enumerate(entries):
            if entry == 0:
                if self.curr:
                    self.result.append(self.curr)
                    self.curr = None
            elif level_remaining == 1 or self.should_stop_pagewalk(entry):
                curr = self.curr
                cnt = self.counters.get(entry, 0)
                if cnt > self.MAX_SAME_PG_TABLE_ENTRY and not curr:
                    continue

                self.counters[entry] = cnt + 1
                flags = self.pageentry_flags(entry)
                if flags == 0:  # only append present pages
                    continue

                # len(entries) == self.pagesz // self.ptrsize, try not to do division here
                size = pagesz * (len(entries) ** (level_remaining - 1))
                if curr:
                    if flags != 0 and flags == curr.flags:
                        curr.memsz += size
                        continue
                    self.result.append(curr)
                    self.curr = None

                # creating a new page
                self.level_idxes[level_remaining] = i
                match self.arch:
                    case "x86-64":
                        bit = self.level_idxes[-1] >> (self.PAGE_INDEX_LEN - 1)  # highest bit
                    case "aarch64":
                        bit = 1 if self.is_kernel else 0
                    case _:
                        raise NotImplementedError()
                nbits = self.ptrsize * 8 - (
                    self.paging_level * self.PAGE_INDEX_LEN + self.page_shift
                )
                addr = bit * ((1 << nbits) - 1)
                for i in range(self.paging_level, 0, -1):
                    addr <<= self.PAGE_INDEX_LEN
                    addr += 0 if i < level_remaining else self.level_idxes[i]
                addr <<= self.page_shift
                self.curr = Page(addr, size, flags, ptrsize, 0)
            else:  # only call when should keep scanning the page tree
                self.level_idxes[level_remaining] = i
                # we need to reduce this recursive call as much as possible
                # each time the level_remaining decremented, garanteed to terminate
                self.scan(entry, level_remaining - 1)
        if level_remaining == self.paging_level and self.curr:
            self.result.append(self.curr)
            self.curr = None

    def walk(self, target: int, entry: int) -> List[PageTableLevel]:
        page_shift = self.page_shift
        result = [PageTableLevel(None, None, None, None) for _ in range(self.paging_level + 1)]
        resolved = offset_mask = None
        for i in range(self.paging_level, 0, -1):
            resolved = None
            shift = page_shift + self.PAGE_INDEX_LEN * (i - 1)
            idx = (target >> shift) & self.PAGE_INDEX_MASK
            addr = entry & self.PAGE_ENTRY_MASK
            if addr not in self.cache:
                break
            entry = self.cache[addr][idx]
            if not entry:
                break
            result[i].virt = addr  # phys addr at this point
            result[i].idx = idx
            result[i].entry = entry
            offset_mask = (1 << shift) - 1
            resolved = (entry & self.PAGE_ENTRY_MASK, offset_mask)
            if self.should_stop_pagewalk(entry):
                break
        if resolved and offset_mask is not None:
            addr, offset_mask = resolved
            result[0].virt = addr + (target & offset_mask)
            result[0].entry = entry
        return result


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

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SIZE(self) -> int:
        a = pwndbg.aglib.typeinfo.load("struct page")
        if a is None:
            # true with the most common set of configurations
            # this struct should always present if a vmlinux is added
            return 0x40
        # needs to be rounded up to a power of 2 (consider the layout of vmemmap)
        return 1 << math.ceil(math.log2(a.sizeof))

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def STRUCT_PAGE_SHIFT(self) -> int:
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

    def handle_kernel_pages(self, pages: Tuple[Page, ...]) -> None:
        # this is arch dependent
        raise NotImplementedError()

    def kbase_helper(self, address: int) -> int | None:
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

    def pagewalk(self, target: int, entry: int | None) -> Tuple[PageTableLevel, ...]:
        raise NotImplementedError()

    def pagetable_scan(self, entry: int | None = None) -> List[Page]:
        raise NotImplementedError()

    @property
    def PAGE_ENTRY_MASK(self) -> int:
        return ~((1 << self.page_shift) - 1) & ((1 << self.va_bits) - 1)

    @property
    def PAGE_INDEX_LEN(self) -> int:
        return self.page_shift - math.ceil(math.log2(pwndbg.aglib.arch.ptrsize))

    @property
    def PAGE_INDEX_MASK(self) -> int:
        return (1 << (self.PAGE_INDEX_LEN)) - 1

    @pwndbg.lib.cache.cache_until("stop")
    def scan_pagetable(self, entry: int, is_kernel: bool) -> PageTableScan | None:
        # only two possible return values: https://qemu-project.gitlab.io/qemu/system/gdb.html
        oldval = pwndbg.dbg.selected_inferior().send_remote("qqemu.PhyMemMode").decode()
        pwndbg.dbg.selected_inferior().send_remote("Qqemu.PhyMemMode:1")
        if pwndbg.dbg.selected_inferior().send_remote("qqemu.PhyMemMode") != b"1":
            return None
        try:
            scan = PageTableScan(self, is_kernel)
            scan.scan(entry, self.paging_level)
        finally:  # so that the PhyMemMode value is always restored
            pwndbg.dbg.selected_inferior().send_remote(f"Qqemu.PhyMemMode:{oldval}")
        return scan

    def pagewalk_helper(self, target: int, entry: int) -> Tuple[PageTableLevel, ...]:
        base = self.physmap
        if entry > base:
            # user inputted a physmap address as pointer to pgd
            entry -= base
        scan = self.scan_pagetable(entry, pwndbg.aglib.memory.is_kernel(target))
        if scan is None:
            return ()
        result = scan.walk(target, entry)
        for i, level in enumerate(result):
            if level.virt is None:
                continue
            level.virt = level.virt + base - self.phys_offset
            level.name = self.pagetable_level_names[i]
        return tuple(result)

    def pagetable_scan_helper(self, entry: int, is_kernel: bool = False) -> List[Page]:
        scan = self.scan_pagetable(entry, is_kernel)
        if scan is None:
            return []
        return scan.result

    def pageentry_bitflags(self, level: int) -> BitFlags:
        raise NotImplementedError()

    def should_stop_pagewalk(self, level: int) -> bool:
        raise NotImplementedError()

    @property
    def phys_offset(self) -> int:
        return 0

    @property
    def va_bits(self) -> int:
        raise NotImplementedError()

    @property
    def pagetable_level_names(self) -> Tuple[str, ...]:
        raise NotImplementedError()

    def pageentry_flags(self, entry: int) -> int:
        raise NotImplementedError()


class x86_64PagingInfo(ArchPagingInfo):
    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pagetable_level_names(self) -> Tuple[str, ...]:
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
    def get_vmalloc_vmemmap_bases(self) -> Tuple[int, int]:
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
    def physmap(self) -> int:
        result = pwndbg.aglib.kernel.symbol.try_usymbol("page_offset_base")
        if result is None:
            result = first_kernel_page_start()
        return result

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self) -> int | None:
        idt_entries = pwndbg.aglib.kernel.get_idt_entries()
        if len(idt_entries) == 0:
            return None
        return self.kbase_helper(idt_entries[0].offset)

    @property
    def page_shift(self) -> int:
        return 12

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmalloc(self) -> int:
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
    def vmemmap(self) -> int:
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

    def handle_kernel_pages(self, pages: Tuple[Page, ...]) -> None:
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

    def pagewalk(self, target: int, entry: int | None) -> Tuple[PageTableLevel, ...]:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        return self.pagewalk_helper(target, entry)

    def pagetable_scan(self, entry: int | None = None) -> List[Page]:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        return self.pagetable_scan_helper(entry)

    def pageentry_bitflags(self, _: int) -> BitFlags:
        return BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("U", 2), ("W", 1), ("P", 0)])

    def should_stop_pagewalk(self, entry: int) -> bool:
        return entry & (1 << 7) > 0

    def pageentry_flags(self, entry: int) -> int:
        if entry & 1 == 0:  # not present
            return 0
        flags = Page.R_OK
        if entry & (1 << 1):
            flags |= Page.W_OK
        if entry & (1 << 63) == 0:
            flags |= Page.X_OK
        return flags


class Aarch64PagingInfo(ArchPagingInfo):
    def __init__(self) -> None:
        self.VMEMMAP_START = self.VMEMMAP_SIZE = self.PAGE_OFFSET = None

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pagetable_level_names(self) -> Tuple[str, ...]:
        match self.paging_level:
            case 4:
                return ("Page", "L3", "L2", "L1", "L0")
            case 3:
                return ("Page", "L3", "L2", "L1")
            case 2:
                return ("Page", "L3", "L2")
        return ()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def tcr_el1(self) -> BitFlags:
        tcr = pwndbg.lib.regs.aarch64_tcr_flags
        tcr.value = pwndbg.aglib.regs.read_reg("TCR_EL1")
        return tcr

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def va_bits(self) -> int:
        id_aa64mmfr2_el1 = pwndbg.lib.regs.aarch64_mmfr_flags
        id_aa64mmfr2_el1.value = pwndbg.aglib.regs.read_reg("ID_AA64MMFR2_EL1")
        feat_lva = id_aa64mmfr2_el1.value is not None and id_aa64mmfr2_el1["VARange"] == 0b0001
        va_bits: int = 64 - self.tcr_el1["T1SZ"]  # this is prob only `vabits_actual`
        self.PAGE_OFFSET = self._PAGE_OFFSET(va_bits)  # physmap base address without KASLR
        if feat_lva:
            va_bits = min(52, va_bits)
        return va_bits

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def va_bits_min(self) -> int:
        return 48 if self.va_bits > 48 else self.va_bits

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmalloc(self) -> int:
        # also includes KASAN and kernel module regions
        return self._PAGE_END(self.va_bits_min)

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def physmap(self) -> int:
        return first_kernel_page_start()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kbase(self) -> int:
        return self.kbase_helper(pwndbg.aglib.regs.read_reg("vbar"))

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kversion(self) -> Tuple[int, ...] | None:
        return pwndbg.aglib.kernel.krelease()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def module_start(self) -> int:
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

    def _PAGE_OFFSET(self, va: int) -> int:  # aka PAGE_START
        return (-(1 << va)) & 0xFFFFFFFFFFFFFFFF

    def _PAGE_END(self, va: int) -> int:
        return (-(1 << (va - 1))) & 0xFFFFFFFFFFFFFFFF

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def vmemmap(self) -> int:
        _ = self.va_bits_min
        if self.kversion is None or self.PAGE_OFFSET is None:
            return INVALID_ADDR
        vmemmap_shift = self.page_shift - self.STRUCT_PAGE_SHIFT
        # self.PAGE_OFFSET is set by self.va_bits(_min) so must exist
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
    def pci(self) -> int:
        if self.kversion is None or self.VMEMMAP_START is None or self.VMEMMAP_SIZE is None:
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
    def fixmap(self) -> int:
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
    def ksize(self) -> int:
        start = pwndbg.aglib.symbol.lookup_symbol_addr("_text")
        end = pwndbg.aglib.symbol.lookup_symbol_addr("_end")
        if start is not None and end is not None:
            return end - start
        # fallback
        return 100 << 21  # 100M

    @property
    @pwndbg.lib.cache.cache_until("objfile")
    def page_shift_heuristic(self) -> int:
        default_val = 12
        sym = pwndbg.aglib.symbol.lookup_symbol_addr("copy_page_to_iter")
        if sym is not None:
            pattern = re.compile(r".*(0x1000|0x10000|0x4000)")
            addr = int(sym)
            # sanity check.
            if not pwndbg.aglib.memory.peek(addr):
                return default_val

            for _ in range(50):
                # It is **crucial** that we don't enhance, because enhancing will run vmmap
                # which will end up running this code, causing infinite recursion.
                # https://github.com/pwndbg/pwndbg/actions/runs/20342890859/job/58446963784?pr=3512
                instr: PwndbgInstruction = pwndbg.aglib.disasm.disassembly.get_one_instruction(
                    addr, enhance=False
                )

                if instr.mnemonic == "MOV" and (result := pattern.search(instr.op_str)) is not None:
                    return int(math.log2(int(result.group(1), 16)))

                addr = instr.next

        return default_val

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
    @pwndbg.lib.cache.cache_until("stop")
    def paging_level(self) -> int:
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
        if self.VMEMMAP_START is None or self.VMEMMAP_SIZE is None or self.PAGE_OFFSET is None:
            return ()
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

    def adjust(self, name: str) -> str:
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

    def handle_kernel_pages(self, pages: Tuple[Page, ...]) -> None:
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
    def phys_offset(self) -> int:
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

    def pagewalk(self, target: int, entry: int | None) -> Tuple[PageTableLevel, ...]:
        if entry is None:
            if pwndbg.aglib.memory.is_kernel(target):
                entry = pwndbg.aglib.regs.read_reg("TTBR1_EL1")
            else:
                entry = pwndbg.aglib.regs.read_reg("TTBR0_EL1")
        entry |= 3  # marks the entry as a table
        return self.pagewalk_helper(target, entry)

    def pagetable_scan(self, entry: int | None = None) -> List[Page]:
        # assumes entry should be from `kcurrent --set` and should be TTBR0_EL1 for a task
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("TTBR0_EL1")
        result = self.pagetable_scan_helper(entry | 3, is_kernel=False)
        if pwndbg.aglib.memory.is_kernel(pwndbg.aglib.regs.pc):
            result += self.pagetable_scan_helper(
                pwndbg.aglib.regs.read_reg("TTBR1_EL1") | 3, is_kernel=True
            )
        return result

    def pageentry_bitflags(self, level: int) -> BitFlags:
        if level != 0:
            # block or page
            return BitFlags([("UNX", 54), ("PNX", 53), ("AP", (6, 7))])
        return BitFlags([("UNX", 60), ("PNX", 59), ("AP", (61, 62))])

    def should_stop_pagewalk(self, entry: int) -> bool:
        return (entry & 1) == 0 or (entry & 3) == 1

    def pageentry_flags(self, entry: int) -> int:
        if entry & 1 == 0:
            return 0
        flags = Page.R_OK
        if (entry >> 53) & 3 != 3:
            flags |= Page.X_OK
        ap = (entry >> 6) & 3
        if ap == 1 or ap == 0:
            flags |= Page.W_OK
        return flags
