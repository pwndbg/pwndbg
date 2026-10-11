from __future__ import annotations

import math
import re

import pwndbg
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.vmmap
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.lib.cache
import pwndbg.lib.regs
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.lib.memory import Page
from pwndbg.lib.regs import BitFlags

from ..paging import BIT
from ..paging import INVALID_ADDR
from ..paging import PageTableLevel
from ..paging import PagewalkResult
from ..paging import Paging
from ..paging import first_kernel_page_start


class aarch64Paging(Paging):
    def __init__(self) -> None:
        self.VMEMMAP_START = self.VMEMMAP_SIZE = self.PAGE_OFFSET = None

    def virt_to_phys(self, virt: int) -> int:
        _virt: int | None = virt
        if not (pwndbg.aglib.memory.is_kernel(virt) and virt < self.vmalloc):
            # if not within physmap range, first find the physmap address
            _virt = self.pagewalk(virt).virt
        if _virt is None:
            _virt = virt
        return _virt - self.physmap + self.ram_phys_start

    def phys_to_virt(self, phys: int) -> int:
        # https://elixir.bootlin.com/linux/v6.16.4/source/arch/arm64/include/asm/memory.h#L356
        return phys - self.ram_phys_start + self.physmap

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    def pfn_to_page(self, pfn: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (pfn << self.STRUCT_PAGE_SHIFT) + self.vmemmap

    def page_to_pfn(self, page: int) -> int:
        # assumption: SPARSEMEM_VMEMMAP memory model used
        # FLATMEM or SPARSEMEM not (yet) implemented
        return (page - self.vmemmap) >> self.STRUCT_PAGE_SHIFT

    @staticmethod
    def paging_enabled() -> bool:
        # AArch64 system control register: newer QEMU releases (tested on
        # 10.2.0) expose it as `SCTLR_EL1`; older releases used the generic
        # `SCTLR`. Bit 0 (M) is the MMU-enable flag in either case. See
        # #3871 / #3875.
        return int(pwndbg.aglib.regs.read_reg("SCTLR_EL1", "SCTLR")) & BIT(0) != 0

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
                instr: PwndbgInstruction | None = (
                    pwndbg.aglib.disasm.disassembly.get_one_instruction(addr, enhance=False)
                )

                if instr is None:
                    break

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

    def pagewalk(self, target: int, entry: int | None = None, virt: bool = True) -> PagewalkResult:
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
