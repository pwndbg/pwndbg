from __future__ import annotations

import re

from ..symbol import ArchSymbols


class x86_64Symbols(ArchSymbols):
    # op ... [... +/- (0x...)]
    # if negative, the `-0x...`` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def qword_op_reg_memoff(
        self, disass: str, op: str, sign: str = "-", nth: int = 0
    ) -> int | None:
        result = self.regex(disass, rf"{op}.*\[.*{re.escape(sign)}\s(0x[0-9a-f]+)\]", nth)
        if result is not None:
            if sign == "-":
                return (1 << 64) - int(result.group(1), 16)
            return int(result.group(1), 16)
        return None

    # op [... +/- (0x...)] ...
    # if negative, the `-0x...`` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def dword_op_memoff_reg(
        self, disass: str, op: str, first: bool = True, nth: int = 0
    ) -> int | None:
        r = rf"{op}.*\[.*([+-])\s(0x[0-9a-f]{{1,8}})\]\s*,"
        if not first:
            r = rf"{op}.*,\s*\[.*([+-])\s(0x[0-9a-f]{{1,8}})\]"
        result = self.regex(disass, r, nth)
        if result is None:
            return None
        value = int(result.group(2), 16)
        return (1 << 64) - value if result.group(1) == "-" else value

    # mov reg, <kernel address as a constant>
    def qword_mov_reg_const(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(disass, r"mov.*(0x[0-9a-f]{16})", nth)
        if result is not None:
            return int(result.group(1), 16)
        return None

    def dword_mov_reg_const(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(disass, r"mov.*(0x[0-9a-f]{1,8})\b(?!\])", nth)
        if result is not None:
            return int(result.group(1), 16)
        return None

    def qword_mov_reg_ripoff(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(
            " ".join(disass.splitlines()),
            r"mov.*\[rip\s([\+\-]\s0x[0-9a-f]+)\]\s(0x[0-9a-f]{16})",
            nth,
        )
        if result is not None:
            return int(result.group(1).replace(" ", ""), 16) + int(result.group(2), 16)
        return None

    def _node_data(self) -> int | None:
        disass = self.disass(self.node_data_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_op_reg_memoff(disass, op="mov", sign="-")) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _slab_caches(self) -> int | None:
        disass = self.disass(self.slab_caches_heuristic_func)
        if not disass:
            return None
        return self.qword_mov_reg_const(disass)

    def _per_cpu_offset(self) -> int | None:
        disass = self.disass(self.per_cpu_offset_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_op_reg_memoff(disass, op="add", sign="-")) is not None:
            return result
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result
        return self.qword_mov_reg_ripoff(disass)

    def _modules(self) -> int | None:
        disass = self.disass(self.modules_heuristic_func)
        if not disass:
            return None
        return self.qword_mov_reg_ripoff(disass)

    def _db_list(self) -> int | None:
        offset = 0x10  # offset of the lock
        disass = self.disass(self.db_list_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result - offset
        return None

    def _map_idr(self) -> int | None:
        disass = self.disass(self.map_idr_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass, nth=1)) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _prog_idr(self) -> int | None:
        disass = self.disass(self.prog_idr_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass, nth=1)) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _current_task(self) -> int | None:
        disass = self.disass(self.current_task_heuristic_func)
        if not disass:
            return None
        if (result := self.dword_mov_reg_const(disass)) is not None:
            return result
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result
        return self.dword_op_memoff_reg(disass, "mov", True)
