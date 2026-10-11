from __future__ import annotations

import re

import pwndbg.aglib

from ..symbol import ArchSymbols


class Aarch64Symbols(ArchSymbols):
    # adrp x?, <kernel address>
    # add x?, x?, #0x...
    def qword_adrp_add_const(self, disass: str, nth: int = 0) -> int | None:
        prev = ""
        for line in disass.splitlines():
            if "adrp" in prev and "add" in line:
                result = self.regex(prev, r"\,\s*0x([0-9a-f]+)", nth=0)
                tmp = None
                if result is not None:
                    tmp = int(result.group(1), 16)
                result = self.regex(line, r"#0x([0-9a-f]+)", nth=0)
                if result is not None and tmp is not None:
                    if nth == 0:
                        return tmp + int(result.group(1), 16)
                    nth -= 1
            prev = line
        return None

    def _node_data(self) -> int | None:
        disass = self.disass(self.node_data_heuristic_func)
        if not disass:
            return None
        return self.qword_adrp_add_const(disass)

    def _slab_caches(self) -> int | None:
        disass = self.disass(self.slab_caches_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass)
        if result:
            return result
        # adrp x<num>, 0x....
        # ...
        # add x<num>, x<num>, #0x...
        # ...
        # add x1, x<num>, #0x...
        pattern = re.compile(
            r"adrp\s+x(\d+),\s+0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x\1,\s+x\1,\s+#0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x1,\s+x\1,\s+#0x([0-9a-fA-F]+)",
            re.DOTALL,
        )
        m = pattern.search(disass)
        if m is None:
            return None
        return sum(int(m.group(i), 16) for i in [2, 3, 4])

    def _per_cpu_offset(self) -> int | None:
        disass = self.disass(self.per_cpu_offset_heuristic_func)
        if not disass:
            return None
        return self.qword_adrp_add_const(disass)

    def _modules(self) -> int | None:
        disass = self.disass(self.modules_heuristic_func)
        if not disass:
            return None
        # adrp x<num>, 0x....
        # ...
        # add x<num>, x<num>, #0x...
        # ...
        # ldr x?, [x<num>, #0x]!...
        pattern = re.compile(
            r"adrp\s+x(\d+),\s+0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x\1,\s+x\1,\s+#0x([0-9a-fA-F]+).*?\n"
            r".*?ldr\s+x\d+,\s+\[x\1,\s+#0x([0-9a-fA-F]+)\]!",
            re.DOTALL,
        )
        m = pattern.search(disass)
        if m is None:
            return None
        return sum(int(m.group(i), 16) for i in [2, 3, 4])

    def _db_list(self) -> int | None:
        offset = 0x10  # offset of the lock
        disass = self.disass(self.db_list_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass)
        if result is not None:
            return result - offset
        return None

    def _map_idr(self) -> int | None:
        disass = self.disass(self.map_idr_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass, nth=1)
        if result is not None:
            return result
        return self.qword_adrp_add_const(disass)

    def _prog_idr(self) -> int | None:
        disass = self.disass(self.prog_idr_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass, nth=1)
        if result is not None:
            return result
        return self.qword_adrp_add_const(disass)

    @property
    def current_task(self) -> int | None:
        return pwndbg.aglib.regs.read_reg("sp_el0")
