from __future__ import annotations

from typing import Generator

import pwndbg.aglib.arch


def find_fastbin_size(mem: bytes, max_size: int, step: int) -> Generator[int, None, None]:
    psize = pwndbg.aglib.arch.ptrsize
    min_fast = 4 * psize

    for i in range(0, len(mem), step):
        candidate = mem[i : i + psize]
        if len(candidate) == psize:
            value = pwndbg.aglib.arch.unpack(candidate)

            # Clear any flags
            value &= ~0xF

            if value < min_fast:
                continue

            # The value must be less than or equal to the max size we're looking
            # for, but still be able to reach the target address
            if value <= max_size <= i + value:
                yield i - psize
