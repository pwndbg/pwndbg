from __future__ import annotations

import pwndbg
import pwndbg.aglib

from ..paging import BIT
from ..paging import Paging


class rv64Paging(Paging):
    @staticmethod
    def paging_enabled():
        return (
            int(pwndbg.aglib.regs.read_reg("satp")) & (BIT(60) | BIT(61) | BIT(62) | BIT(63)) != 0
        )
