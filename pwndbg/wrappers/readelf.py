from __future__ import annotations

from enum import Enum
from typing import Dict
from typing import List

import pwndbg.wrappers

cmd_name = "readelf"


class RelocationType(Enum):
    # For x86_64, some details about these flag can be found in 4.4.1 Relocation Types in https://www.intel.com/content/dam/develop/external/us/en/documents/mpx-linux64-abi.pdf
    # The definitions of these flags can be found in this file: https://elixir.bootlin.com/glibc/glibc-2.37/source/elf/elf.h
    JUMP_SLOT = 1  # e.g.: R_X86_64_JUMP_SLOT
    GLOB_DAT = 2  # e.g.: R_X86_64_GLOB_DAT
    IRELATIVE = 3  # e.g.: R_X86_64_IRELATIVE


@pwndbg.wrappers.OnlyWithCommand(cmd_name)
def get_got_entry(local_path: str) -> Dict[RelocationType, List[str]]:
    # --wide is for showing the full information, e.g.: R_X86_64_JUMP_SLOT instead of R_X86_64_JUMP_SLO
    cmd = get_got_entry.cmd + ["--relocs", "--wide", local_path]
    readelf_out = pwndbg.wrappers.call_cmd(cmd)

    entries: Dict[RelocationType, List[str]] = {category: [] for category in RelocationType}
    for line in readelf_out.splitlines():
        if not line or not line[0].isdigit() or " " not in line:
            continue
        category = line.split()[2]
        # TODO/FIXME: There's a bug here, somehow the IRELATIVE relocation might point to somewhere in .data.rel.ro, which is not in .got or .got.plt
        for c in RelocationType:
            if c.name in category:
                entries[c].append(line)
    return entries
