from __future__ import annotations

import pwndbg
import pwndbg.aglib

from ..paging import BIT
from ..paging import Paging


class i386Paging(Paging):
    def phys_to_virt(self, phys: int) -> int:
        return pwndbg.aglib.arch.unsigned(phys + self.physmap)

    def phys_to_pfn(self, phys: int) -> int:
        return phys >> self.page_shift

    def pfn_to_phys(self, pfn: int) -> int:
        return pfn << self.page_shift

    @property
    def enabled(self) -> bool:
        return int(pwndbg.aglib.regs.read_reg("cr0")) & BIT(31) != 0
