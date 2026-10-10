from __future__ import annotations

import math
import struct
from collections.abc import Callable
from dataclasses import dataclass

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.vmmap
import pwndbg.aglib.memory
import pwndbg.aglib.typeinfo
import pwndbg.lib.cache
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
    def __init__(self, pi: Paging) -> None:
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


class Paging:
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
