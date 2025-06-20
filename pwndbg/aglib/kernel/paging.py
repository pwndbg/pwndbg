from __future__ import annotations

import math
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.memory

ENTRYMASK = ~((1 << 12) - 1) & ((1 << 51) - 1)


@pwndbg.lib.cache.cache_until("start", "stop")
def get_memory_map_raw() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return pwndbg.aglib.kernel.vmmap.kernel_vmmap(False)


def guess_physmap():
    # this is mostly true
    # https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
    for page in get_memory_map_raw():
        if page.start and pwndbg.aglib.memory.is_kernel(page.start):
            return page.start


class AddressMarkers:
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
    def STRUCT_PAGE_SIZE(self):
        a = pwndbg.aglib.typeinfo.load("struct page")
        if a is None:
            return 0x40
        return a.sizeof

    @property
    def STRUCT_PAGE_SHIFT(self):
        return int(math.log2(self.STRUCT_PAGE_SIZE))

    @property
    def physmap(self):
        raise NotImplementedError()

    @property
    def vmalloc(self):
        raise NotImplementedError()

    @property
    def vmemmap(self):
        raise NotImplementedError()

    @property
    def kbase_approx_address(self) -> int:
        raise NotImplementedError()

    @property
    def page_shift(self) -> int:
        raise NotImplementedError()

    @property
    def addr_marker_sz(self) -> int:
        raise NotImplementedError()

    def markers_fallback(self) -> Tuple[Tuple[str, int], ...]:
        raise NotImplementedError()

    def adjust(self, name: str) -> str:
        raise NotImplementedError()

    def markers(self) -> Tuple[Tuple[str, int], ...]:
        address_markers = pwndbg.aglib.symbol.lookup_symbol_addr("address_markers")
        if address_markers is not None:
            sections = [(self.USERLAND, 0)]
            value = 0
            name = None
            for i in range(20):
                value = pwndbg.aglib.memory.u64(address_markers + i * self.addr_marker_sz)
                if value > 0:
                    name_ptr = pwndbg.aglib.memory.u64(
                        address_markers + i * self.addr_marker_sz + 8
                    )
                    name = None
                    if name_ptr > 0:
                        name = pwndbg.aglib.memory.string(name_ptr).decode()
                        name = self.adjust(name)
                    sections.append((name, value))
                if value == 0xFFFFFFFFFFFFFFFF:
                    break
            return tuple(sections)
        return self.markers_fallback()

    def handle_kernel_pages(self, pages, kernel_idx):
        # this is arch dependent
        raise NotImplementedError()

    @property
    def kbase(self):
        address = self.kbase_approx_address
        for mapping in get_memory_map_raw():
            # should be page aligned -- either from pt-dump or info mem

            # only search in kernel mappings:
            # https://www.kernel.org/doc/html/v5.3/arm64/memory.html
            if not pwndbg.aglib.memory.is_kernel(mapping.vaddr):
                continue

            if not mapping.execute:
                continue

            if address in mapping:
                return mapping.vaddr

        return None


class x86_64Markers(AddressMarkers):
    @property
    def physmap(self):
        result = pwndbg.aglib.symbol.lookup_symbol_addr("page_offset_base")
        if result is not None:
            if pwndbg.aglib.memory.peek(result):
                result = pwndbg.aglib.memory.u64(result)
            else:
                return None
            if result is not None:
                return result
        return guess_physmap()

    @property
    def vmalloc(self):
        return pwndbg.aglib.symbol.lookup_symbol_value("vmalloc_base")

    @property
    def vmemmap(self):
        return pwndbg.aglib.symbol.lookup_symbol_value("vmemmap_base")

    @property
    def kbase_approx_address(self) -> int:
        # if self.uses_5lvl_paging():
        #     # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L41
        #     self.PAGE_OFFSET = 0xFF11000000000000
        #     # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L131
        #     self.VMEMMAP_START = 0xFFD4000000000000
        # else:
        #     # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/page_64_types.h#L42
        #     self.PAGE_OFFSET = 0xFFFF888000000000
        #     # https://elixir.bootlin.com/linux/v6.2/source/arch/x86/include/asm/pgtable_64_types.h#L130
        #     self.VMEMMAP_START = 0xFFFFEA0000000000
        return pwndbg.aglib.kernel.get_idt_entries()[0].offset

    @property
    def page_shift(self) -> int:
        return 12

    def markers_fallback(self) -> Tuple[Tuple[str, int], ...]:
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
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

    @property
    def addr_marker_sz(self):
        return 0x18

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

    def handle_kernel_pages(self, pages, kernel_idx):
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
            if page.execute and page.start != self.kbase:
                page.objfile = self.KERNELDRIVER
                has_loadable_driver = True
            if pwndbg.aglib.regs[pwndbg.aglib.regs.stack] in page:
                page.objfile = "kernel [stack]"


class Aarch64Markers(AddressMarkers):
    def _page_offset(self, va):
        return (-1 << va) + 2**64

    def _page_end(self, va):
        return (-1 << (va - 1)) + 2**64

    @property
    def tcr_el1(self):
        tcr_el1 = pwndbg.lib.regs.aarch64_tcr_flags
        tcr_el1.value = pwndbg.aglib.regs.TCR_EL1
        return tcr_el1

    @property
    def va_bits(self) -> int:
        return 64 - self.tcr_el1["T1SZ"]

    @property
    def va_bits_min(self) -> int:
        # TODO: this is probably not entirely correct
        # https://elixir.bootlin.com/linux/v6.16-rc2/source/arch/arm64/include/asm/memory.h#L56
        va_bits = self.va_bits
        return 48 if va_bits > 48 else va_bits

    @property
    def physmap(self):
        # addr = pwndbg.aglib.symbol.lookup_symbol_addr("memstart_addr")
        # if addr is None:
        #     return guess_physmap()
        # return pwndbg.aglib.memory.u(addr)
        # return self._page_offset(self.va_bits)
        return guess_physmap()

    @property
    def physmap_end(self):
        res = None
        for page in get_memory_map_raw():
            if page.end >= self._page_end(self.va_bits_min):
                break
            res = page.end
        return res

    @property
    def module_start(self):
        return self._page_end(self.va_bits_min)

    @property
    def module_end(self):
        return self.module_start + 0x80000000

    @property
    def vmalloc(self):
        # https://elixir.bootlin.com/linux/v6.13.12/source/arch/arm64/include/asm/memory.h#L47
        return self.module_end

    @property
    def vmemmap(self):
        shift = self.page_shift - self.STRUCT_PAGE_SHIFT
        self.VMEMMAP_SIZE = (self.physmap_end - self.physmap) >> shift
        if pwndbg.aglib.kernel.krelease() >= (6, 9):
            for page in get_memory_map_raw():
                if page.start >= -0x40000000 % (1 << 64):
                    return page.start
        if pwndbg.aglib.kernel.krelease() >= (5, 11):
            # Linux 5.11 changed the calculation for VMEMMAP_START
            # https://elixir.bootlin.com/linux/v5.11/source/arch/arm64/include/asm/memory.h#L53
            self.VMEMMAP_SHIFT = self.page_shift - self.STRUCT_PAGE_SHIFT
            return -(1 << (self.va_bits - self.VMEMMAP_SHIFT)) % (1 << 64)
        self.VMEMMAP_SIZE = (self._page_end(self.va_bits_min) - self.physmap) >> shift
        return (-self.VMEMMAP_SIZE - 2 * 1024 * 1024) + 2**64

    @property
    def ksize(self):
        start = pwndbg.aglib.symbol.lookup_symbol_addr("_text")
        end = pwndbg.aglib.symbol.lookup_symbol_addr("_end")
        if start is not None and end is not None:
            return end - start
        # fallback
        return 100 << 21  # 100M

    @property
    def kbase_approx_address(self) -> int:
        return pwndbg.aglib.regs.vbar

    @property
    def page_shift(self) -> int:
        # TODO: this might be arm version dependent
        if self.tcr_el1["TG1"] == 1:
            return 14
        elif self.tcr_el1["TG1"] == 0:
            return 12
        else:
            return 16

    def markers_fallback(self) -> Tuple[Tuple[str, int], ...]:
        return (
            (self.USERLAND, 0),
            (None, 0x8000000000000000),
            (self.PHYSMAP, self.physmap),
            (None, self.physmap_end),
            (self.KERNELDRIVER, self.module_start),
            (self.VMALLOC, self.vmalloc),  # same as module_end
            (self.VMEMMAP, self.vmemmap),
            (None, self.vmemmap + self.VMEMMAP_SIZE),
            # TODO: the computation of the base addresses for PCI and fixmap is version dependent
            #       don't really want to figure that out at the moment since they are not so important
            # ("PCI", self.vmemmap + self.VMEMMAP_SIZE + 0x00800000),
            # ("fixmap", -0x00800000 % (1<<64)),
            (None, 0xFFFFFFFFFFFFFFFF),
        )

    @property
    def addr_marker_sz(self):
        return 0x10

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

    def handle_kernel_pages(self, pages, kernel_idx):
        if kernel_idx is None:
            return
        for i in range(kernel_idx, len(pages)):
            page = pages[i]
            if page.start < self.kbase or page.start > self.kbase + self.ksize:
                continue
            page.objfile = self.KERNELLAND
            if not page.execute:
                if page.write:
                    page.objfile = self.KERNELBSS
                else:
                    page.objfile = self.KERNELRO
            if pwndbg.aglib.regs[pwndbg.aglib.regs.stack] in page:
                page.objfile = "kernel [stack]"


@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def uses_5lvl_paging() -> bool:
    if pwndbg.aglib.kernel.has_debug_syms():
        ops: pwndbg.aglib.kernel.x86_64Ops = pwndbg.aglib.kernel.arch_ops()
        return ops.uses_5lvl_paging()
    pages = get_memory_map_raw()
    for page in pages:
        if page.start & (1 << 63) > 0:
            return page.start < (0xFFF << (4 * 13))
    return False


@pwndbg.aglib.proc.OnlyWithArch(["x86-64"])
def pagewalk(target, entry=None) -> List[Tuple[int | None, int | None]]:
    level = 4
    if uses_5lvl_paging():
        level = 5
    base = pwndbg.aglib.kernel.arch_markers().physmap
    if entry is None:
        entry = pwndbg.aglib.regs["cr3"]
    else:
        entry = int(pwndbg.dbg.selected_frame().evaluate_expression(entry))
    if entry > base:
        # user inputted a physmap address as pointer to pgd
        entry -= base
    result: List[Tuple[int | None, int | None]] = [(None, None)] * (level + 1)
    for i in range(level, 0, -1):
        vaddr = (entry & ENTRYMASK) + base
        if entry & (1 << 7) > 0:
            break
        shift = (i - 1) * 9 + 12
        offset = target & ((1 << shift) - 1)
        idx = (target & (0x1FF << shift)) >> shift
        entry = 0
        try:
            table = pwndbg.aglib.memory.get_typed_pointer("unsigned long", vaddr)
            entry = int(table[idx])
        except Exception as e:
            print(M.warn(f"Exception while page walking: {e}"))
            entry = 0
        if entry == 0:
            return result
        result[i] = (entry, vaddr)
    result[0] = (None, (entry & ENTRYMASK) + base + offset)
    return result
