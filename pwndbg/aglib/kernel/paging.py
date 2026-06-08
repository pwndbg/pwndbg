from __future__ import annotations

import math
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass

import pwndbg
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.kernel.vmmap
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
import pwndbg.lib.memory
import pwndbg.lib.regs
import pwndbg.search
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.lib.memory import Page
from pwndbg.lib.regs import BitFlags

# don't return None but rather an invalid value for address markers
# this way arithmetic ops do not panic if physmap is not found
INVALID_ADDR = 1 << 64


@pwndbg.lib.cache.cache_until("stop")
def first_kernel_page_start() -> int:
    for page in pwndbg.aglib.kernel.vmmap.kernel_vmmap_pages():
        if page.start and pwndbg.aglib.memory.is_kernel(page.start):
            return page.start
    return INVALID_ADDR


@dataclass
class PageTableLevel:
    name: str | None = None
    entry: int | None = None
    virt: int | None = None  # within physmap
    phys: int | None = None  # physcal address
    idx: int | None = None
    level: int | None = None


@dataclass
class PagewalkResult:
    virt: int | None = None  # within physmap
    phys: int | None = None  # physcal address
    entry: int | None = None
    levels: tuple[PageTableLevel, ...] = ()


class PageTableScan:
    def __init__(self, pi: ArchPagingInfo) -> None:
        # from ArchPagingInfo:
        self.paging_level = pi.paging_level
        self.PAGE_ENTRY_MASK = pi.PAGE_ENTRY_MASK
        self.PAGE_INDEX_LEN = pi.PAGE_INDEX_LEN
        self.PAGE_INDEX_MASK = pi.PAGE_INDEX_MASK
        self.page_shift = pi.page_shift
        self.should_stop_pagewalk = pi.should_stop_pagewalk
        # for scanning
        self.pagesz = pi.page_size
        self.ptrsize = pwndbg.aglib.arch.ptrsize
        self.fmt = "<" + ("Q" if self.ptrsize == 8 else "I") * (self.pagesz // self.ptrsize)
        self.cache: dict[tuple[int, int], list[tuple[int, int, int]]] = {}
        self.entry_cache: dict[int, tuple[int]] = {}
        self.arch = pwndbg.aglib.arch.name
        # the default is slightly slower but does not require setting yama.ptrace_scope
        self.read: Callable[[int, int], bytearray] = pwndbg.dbg.selected_inferior().read_memory
        if qm := pwndbg.aglib.qemu.get_qemu_machine():  # note this would fail silently
            self.read = qm.read_physical_memory

    def scan(self, entry: int, is_kernel: bool = False) -> list[Page]:
        """
        this needs to be EXTREMELY optimized as it is used to display context
        making as few functions calls or memory reads as possible
        avoid unnecessary python pointer deferences or repetative computations whenever possible
        when benchmarked on the same linux kernels with the same read method, on average:
        - gdb-pt-dump takes ~0.122 for x64 and 0.562 seconds for aarch64
        - this implementation takes less than 0.0297 seconds to complete for x64 and 0.0492 seconds for aarch64
        --> 4x faster for x64 and 10x faster for aarch64
        """
        entry &= self.PAGE_ENTRY_MASK
        if (entry, self.paging_level) not in self.cache:
            self._scan(entry, self.paging_level)
        result = []
        curr = None
        kernel_prefix_shift = self.paging_level * self.PAGE_INDEX_LEN + self.page_shift
        # assumes the elements in self.cache[*] are sorted and non-overlapping
        for offset, size, flags in self.cache[(entry, self.paging_level)]:
            if self.arch == "x86-64":
                is_kernel = offset >= (1 << 47)
            if is_kernel:
                nbits = self.ptrsize * 8 - kernel_prefix_shift
                offset += ((1 << nbits) - 1) << kernel_prefix_shift
            if curr and offset == curr.end and flags == curr.flags:
                # merge contiguous chunks
                curr.memsz = max(curr.memsz, offset + size - curr.start)
            else:
                if curr:
                    result.append(curr)
                curr = Page(offset, size, flags, 0, self.ptrsize)
        if curr:
            result.append(curr)
        return result

    def _scan(self, addr: int, level: int) -> None:
        pagesz = self.pagesz
        orig = addr
        self.entry_cache[addr] = struct.unpack(self.fmt, self.read(addr, self.pagesz))
        entries = self.entry_cache[addr]
        ranges: list[tuple[int, int, int]] = []
        append = ranges.append
        # the range currently being merged, curr_off == None means there is no current range being merged
        curr_off = None
        curr_sz = curr_flags = 0
        # len(entries) == self.pagesz // self.ptrsize, try not to do division here
        size = pagesz * (len(entries) ** (level - 1))
        # per entry offset relative to the start of the current pagetable,
        # each entry represents `size` bytes of memory, therefore, offset += size for each entry
        offset = 0
        # TODO: prev is used to avoid clustering the vmmap output with espfix ranges (happens for x86-64)
        # consecutive identical pt entries will be clapsed into one. None means not x86-64
        # I believe this is what gdb-pt-dump does as this gives identical output
        prev = 0 if self.arch == "x86-64" and level != 1 else None
        for entry in entries:
            if prev and prev == entry:
                # be aware to not use continue
                pass
            elif entry == 0:
                if curr_off is not None:
                    append((curr_off, curr_sz, curr_flags))
                    curr_off = None
            elif level == 1 or self.should_stop_pagewalk(entry):
                flags = 0
                match self.arch:
                    case "x86-64":
                        flags = Page.R_OK if entry & 1 != 0 else 0
                        flags |= Page.W_OK if entry & (1 << 1) else 0
                        flags |= Page.X_OK if entry & (1 << 63) == 0 else 0
                    case "aarch64":
                        flags = Page.R_OK if entry & 1 != 0 else 0
                        flags |= Page.X_OK if (entry >> 53) & 3 != 3 else 0
                        ap = (entry >> 6) & 3
                        flags |= Page.W_OK if ap in {1, 0} else 0
                if flags & Page.R_OK:  # only append present pages, read bit indicates presence
                    if curr_off is not None:
                        if flags == curr_flags:
                            curr_sz += size
                        else:
                            append((curr_off, curr_sz, curr_flags))
                            curr_off = None
                    if curr_off is None:
                        curr_off, curr_sz, curr_flags = offset, size, flags
            else:
                addr = entry & self.PAGE_ENTRY_MASK
                key = (addr, level - 1)
                if key not in self.cache:
                    # only call when should keep scanning the page tree
                    # we need to reduce this recursive call as much as possible
                    # each time the level is decremented, garanteed to terminate
                    self._scan(addr, level - 1)
                arr = self.cache[key]
                # The following if-blocks are purely for optimization purposes
                # coalesce as much as we can
                left, n = 0, len(arr)
                right = n - 1
                if n > 0:  # merge the first page chunk range if needed
                    if curr_off is not None:
                        roff, rsz, rflags = arr[0]
                        # is the first non-zero entry actually the first (0 th) entry?
                        if rflags == curr_flags and roff == 0:
                            curr_sz += rsz
                            left += 1
                if curr_off is not None and (n > 1 or (n == 1 and left == 0)):
                    append((curr_off, curr_sz, curr_flags))
                    curr_off = None
                if n > 1:  # (prepare to) merge the last page chunk range if needed
                    roff, rsz, rflags = arr[n - 1]
                    # is the last non-zero entry actually the last (e.g. 511 th) entry?
                    if roff + rsz == size:
                        curr_off, curr_sz, curr_flags = offset + roff, rsz, rflags
                        right -= 1
                for roff, rsz, rflags in arr[left : right + 1]:
                    append((offset + roff, rsz, rflags))
            offset += size
            if prev is not None:
                prev = entry
        if curr_off is not None:
            append((curr_off, curr_sz, curr_flags))
        self.cache[(orig, level)] = ranges

    def walk(self, target: int, entry: int) -> PagewalkResult:
        page_shift = self.page_shift
        levels = [PageTableLevel() for _ in range(self.paging_level)]
        resolved = offset_mask = None
        for i in range(self.paging_level - 1, -1, -1):
            resolved = None
            shift = page_shift + self.PAGE_INDEX_LEN * i
            idx = (target >> shift) & self.PAGE_INDEX_MASK
            addr = entry & self.PAGE_ENTRY_MASK
            if addr not in self.entry_cache:
                self.entry_cache[addr] = struct.unpack(self.fmt, self.read(addr, self.pagesz))
            entry = self.entry_cache[addr][idx]
            if not entry:
                break
            levels[i].phys = addr
            levels[i].idx = idx
            levels[i].entry = entry
            levels[i].level = i + 1
            offset_mask = (1 << shift) - 1
            resolved = (entry & self.PAGE_ENTRY_MASK, offset_mask)
            if self.should_stop_pagewalk(entry):
                break
        result = PagewalkResult()
        if resolved and offset_mask is not None:
            addr, offset_mask = resolved
            result.phys = addr + (target & offset_mask)
            result.entry = entry
        result.levels = tuple(levels)
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

    def slab_to_virt(self, slab: int) -> int:
        raise NotImplementedError()

    def virt_to_slab(self, virt: int) -> int:
        raise NotImplementedError()

    @property
    def slab_virtual(self) -> int:
        raise NotImplementedError()

    @property
    def kbase(self) -> int | None:
        raise NotImplementedError()

    @property
    def page_shift(self) -> int:
        raise NotImplementedError()

    @property
    def page_size(self) -> int:
        return 1 << self.page_shift

    @property
    def paging_level(self) -> int:
        raise NotImplementedError()

    def adjust(self, name: str) -> str:
        raise NotImplementedError()

    @pwndbg.lib.cache.cache_until("stop")
    def markers(self) -> tuple[tuple[str | None, int | None], ...]:
        raise NotImplementedError()

    def handle_kernel_pages(self, pages: tuple[Page, ...]) -> None:
        # this is arch dependent
        raise NotImplementedError()

    def _kbase(self, address: int | None) -> int | None:
        if address is None:
            return None
        for mapping in pwndbg.aglib.kernel.vmmap.kernel_vmmap_pages():
            # should be page aligned -- either from pt-dump or info mem

            # only search in kernel mappings:
            # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
            if not pwndbg.aglib.memory.is_kernel(mapping.vaddr):
                continue

            if address in mapping:
                return mapping.vaddr

        return None

    def pagewalk(self, target: int, entry: int | None, virt: bool = True) -> PagewalkResult:
        raise NotImplementedError()

    def pagescan(self, entry: int | None = None) -> list[Page]:
        raise NotImplementedError()

    @property
    def PAGE_ENTRY_MASK(self) -> int:
        return ~(self.page_size - 1) & ((1 << self.va_bits) - 1)

    @property
    def PAGE_INDEX_LEN(self) -> int:
        return self.page_shift - math.ceil(math.log2(pwndbg.aglib.arch.ptrsize))

    @property
    def PAGE_INDEX_MASK(self) -> int:
        return (1 << (self.PAGE_INDEX_LEN)) - 1

    @pwndbg.lib.cache.cache_until("stop")
    def pagetablescan(self, entry: int) -> PageTableScan | None:
        return PageTableScan(self)

    def switch_to_phymem_mode(self) -> tuple[str, bool]:
        oldval = pwndbg.dbg.selected_inferior().send_remote("qqemu.PhyMemMode").decode()
        pwndbg.dbg.selected_inferior().send_remote("Qqemu.PhyMemMode:1")
        # only two possible return values: https://qemu-project.gitlab.io/qemu/system/gdb.html
        success = pwndbg.dbg.selected_inferior().send_remote("qqemu.PhyMemMode") == b"1"
        return oldval, success

    def _pagewalk(self, target: int, entry: int, virt: bool) -> PagewalkResult:
        scan = self.pagetablescan(entry)
        oldval, success = self.switch_to_phymem_mode()
        if not success or not scan:
            return PagewalkResult()
        result = PagewalkResult()
        try:
            result = scan.walk(target, entry)
            if not virt:
                return result
            levels = result.levels
            for level in levels:
                if level.phys is None or level.level is None:
                    continue
                level.virt = level.phys + self.physmap - self.ram_phys_start
                level.name = self.pagetable_level_names[level.level]
            if result.phys is not None:
                result.virt = result.phys + self.physmap - self.ram_phys_start
        except Exception:
            pass
        finally:  # so that the PhyMemMode value is always restored
            pwndbg.dbg.selected_inferior().send_remote(f"Qqemu.PhyMemMode:{oldval}")
        return result

    def _pagescan(self, entry: int, is_kernel: bool = False) -> list[Page]:
        scan = self.pagetablescan(entry)
        oldval, success = self.switch_to_phymem_mode()
        if not success or not scan:
            return []
        result = []
        try:
            result = scan.scan(entry, is_kernel)
        except Exception:
            pass
        finally:  # so that the PhyMemMode value is always restored
            pwndbg.dbg.selected_inferior().send_remote(f"Qqemu.PhyMemMode:{oldval}")
        return result

    def bitflags(self, level: PageTableLevel) -> BitFlags:
        raise NotImplementedError()

    def should_stop_pagewalk(self, entry: int) -> bool:
        raise NotImplementedError()

    @property
    def ram_phys_start(self) -> int:
        return 0

    @property
    def va_bits(self) -> int:
        raise NotImplementedError()

    @property
    def pagetable_level_names(self) -> tuple[str, ...]:
        raise NotImplementedError()


class x86_64PagingInfo(ArchPagingInfo):
    def __init__(self) -> None:
        self.P4D_SHIFT = 39

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
                pwndbg.search.search(target, mappings=[mapping], aligned=pwndbg.aglib.arch.ptrsize),
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
        result: int | None = pwndbg.aglib.kernel.symbol.try_usymbol("page_offset_base")
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
        result: int | None = pwndbg.aglib.kernel.symbol.try_usymbol("vmalloc_base")
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
        result: int | None = pwndbg.aglib.kernel.symbol.try_usymbol("vmemmap_base")
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
        for i, page in enumerate(pages):
            if stack in page:
                page.objfile += " [stack]"

    def pagewalk(self, target: int, entry: int | None, virt: bool = True) -> PagewalkResult:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        if entry is None:
            return PagewalkResult()
        return self._pagewalk(target, entry, virt)

    def pagescan(self, entry: int | None = None) -> list[Page]:
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("cr3")
        if entry is None:
            return []
        return self._pagescan(entry)

    def bitflags(self, level: PageTableLevel) -> BitFlags:
        return BitFlags([("NX", 63), ("PS", 7), ("A", 5), ("U", 2), ("W", 1), ("P", 0)])

    def should_stop_pagewalk(self, entry: int) -> bool:
        return entry & (1 << 7) > 0


class Aarch64PagingInfo(ArchPagingInfo):
    def __init__(self) -> None:
        self.VMEMMAP_START = self.VMEMMAP_SIZE = self.PAGE_OFFSET = None

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pagetable_level_names(self) -> tuple[str, ...]:
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
        tcr.value = pwndbg.aglib.regs.read_reg("TCR_EL1") or 0
        return tcr

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def va_bits(self) -> int:
        id_aa64mmfr2_el1 = pwndbg.lib.regs.aarch64_mmfr_flags
        id_aa64mmfr2_el1.value = pwndbg.aglib.regs.read_reg("ID_AA64MMFR2_EL1") or 0
        feat_lva = id_aa64mmfr2_el1.value is not None and id_aa64mmfr2_el1["VARange"] == 0b0001
        va_bits: int = 64 - self.tcr_el1["T1SZ"]  # this is prob only `vabits_actual`
        self.PAGE_OFFSET = self._PAGE_OFFSET(va_bits)  # physmap base address without KASLR
        if feat_lva:
            va_bits = min(52, va_bits)
        return va_bits

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def va_bits_min(self) -> int:
        return min(self.va_bits, 48)

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
    def kbase(self) -> int | None:
        # AArch64 vector base: QEMU >= ~8.x exposes it as `vbar_el1`; older
        # QEMU releases (and some non-EL1 contexts) expose it as the generic
        # `vbar`. See #3869 / #3875.
        return self._kbase(pwndbg.aglib.regs.read_reg("vbar_el1", "vbar"))

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def kversion(self) -> tuple[int, ...] | None:
        return pwndbg.aglib.kernel.krelease()

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def module_start(self) -> int | None:
        if self.kbase is None:
            return None
        res = None
        for page in pwndbg.aglib.kernel.vmmap.kernel_vmmap_pages()[::-1]:
            if page.start >= self.kbase:
                continue
            if page.start < self.vmalloc:
                break
            if page.execute:
                res = page.start
                break
        return res

    def _PAGE_OFFSET(self, va: int) -> int:  # aka PAGE_START
        return pwndbg.aglib.arch.unsigned(-(1 << va))

    def _PAGE_END(self, va: int) -> int:
        return pwndbg.aglib.arch.unsigned(-(1 << (va - 1)))

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
            self.VMEMMAP_START = pwndbg.aglib.arch.unsigned(-self.VMEMMAP_SIZE - 0x00200000)
        elif self.kversion < (6, 9):
            self.VMEMMAP_SIZE = (
                self._PAGE_END(self.va_bits_min) - self.PAGE_OFFSET
            ) >> vmemmap_shift
            self.VMEMMAP_START = self._PAGE_OFFSET(self.va_bits - vmemmap_shift)
        else:
            VMEMMAP_RANGE = self._PAGE_END(self.va_bits_min) - self.PAGE_OFFSET
            self.VMEMMAP_SIZE = (VMEMMAP_RANGE >> self.page_shift) * self.STRUCT_PAGE_SIZE
            self.VMEMMAP_START = pwndbg.aglib.arch.unsigned(-0x40000000 - self.VMEMMAP_SIZE)

        # obtained through debugging -- kaslr offset of physmap determines the offset of vmemmap
        vmemmap_kaslr = (self.physmap - self.PAGE_OFFSET - self.ram_phys_start) >> vmemmap_shift
        return self.VMEMMAP_START + vmemmap_kaslr

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def pci(self) -> int | None:
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
        if self.pci and self.kversion < (5, 11):
            FIXADDR_TOP = self.pci - 0x00200000  # 2M
        elif self.VMEMMAP_START and self.kversion < (6, 9):
            FIXADDR_TOP = self.VMEMMAP_START - 0x02000000  # 32M
        else:
            FIXADDR_TOP = pwndbg.aglib.arch.unsigned(-0x00800000)
        # https://elixir.bootlin.com/linux/v6.16.5/source/arch/arm64/include/asm/fixmap.h#L102
        # 0x1000 is an upper estimate
        FIXADDR_SIZE = 0x1000 << self.page_shift
        return FIXADDR_TOP - FIXADDR_SIZE

    @property
    @pwndbg.lib.cache.cache_until("stop")
    def ksize(self) -> int:
        start = pwndbg.aglib.symbol.lookup_symbol_addr("_text")
        if start is None:
            start = self.kbase
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
    def markers(self) -> tuple[tuple[str | None, int | None], ...]:
        address_markers = pwndbg.aglib.symbol.lookup_symbol_addr("address_markers")
        if address_markers is not None:
            sections: list[tuple[str | None, int | None]] = [(self.USERLAND, 0)]
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
                if value == pwndbg.aglib.arch.unsigned(-1):
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
            (None, pwndbg.aglib.arch.unsigned(-1)),
        )

    def adjust(self, name: str) -> str:
        name = name.lower()
        if "end" in name:
            return ""
        if "linear" in name:
            return self.PHYSMAP
        if "modules" in name:
            return self.KERNELDRIVER
        if self.VMEMMAP in name:
            return self.VMEMMAP
        if self.VMALLOC in name:
            return self.VMALLOC
        return " ".join(name.strip().split()[:-1])

    def handle_kernel_pages(self, pages: tuple[Page, ...]) -> None:
        if self.kbase is None:
            return
        stack = pwndbg.aglib.regs.read_reg(pwndbg.aglib.regs.stack)
        for i in range(len(pages)):
            page = pages[i]
            if self.module_start and self.module_start <= page.start < self.kbase:
                page.objfile = self.KERNELDRIVER
            elif self.kbase <= page.start < self.kbase + self.ksize:
                page.objfile = self.KERNELLAND
                if not page.execute:
                    if page.write:
                        page.objfile = self.KERNELBSS
                    else:
                        page.objfile = self.KERNELRO
            if stack and stack in page:
                page.objfile += " [stack]"

    @property
    @pwndbg.lib.cache.cache_until("start")
    def ram_phys_start(self) -> int:
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

    def pagewalk(self, target: int, entry: int | None, virt: bool = True) -> PagewalkResult:
        if pwndbg.aglib.memory.is_kernel(target):
            entry = pwndbg.aglib.regs.read_reg("TTBR1_EL1")
        elif entry is None:
            entry = pwndbg.aglib.regs.read_reg("TTBR0_EL1")
        if entry is None:
            return PagewalkResult()
        entry |= 3  # marks the entry as a table
        return self._pagewalk(target, entry, virt)

    def pagescan(self, entry: int | None = None) -> list[Page]:
        # assumes entry should be from `kcurrent --set` and should be TTBR0_EL1 for a task
        if entry is None:
            entry = pwndbg.aglib.regs.read_reg("TTBR0_EL1")
        if entry is None:
            return []
        result = self._pagescan(entry | 3, is_kernel=False)
        if pwndbg.aglib.memory.is_kernel(pwndbg.aglib.regs.pc):
            entry = pwndbg.aglib.regs.read_reg("TTBR1_EL1")
            if entry is None:
                return []
            result += self._pagescan(entry | 3, is_kernel=True)
        return result

    def bitflags(self, level: PageTableLevel) -> BitFlags:
        if level.level == 1 or not level.entry or self.should_stop_pagewalk(level.entry):
            # block or page
            return BitFlags([("UNX", 54), ("PNX", 53), ("AP", (6, 7))])
        return BitFlags([("UNX", 60), ("PNX", 59), ("AP", (61, 62))])

    def should_stop_pagewalk(self, entry: int) -> bool:
        return (entry & 1) == 0 or (entry & 3) == 1
