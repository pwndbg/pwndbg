import struct

import pwndbg.gdblib.arch


def find_fastbin_size(mem: bytes, max_size: int, step: int):
    psize = pwndbg.gdblib.arch.ptrsize
    min_fast = 4 * psize
    fmt = {"little": "<", "big": ">"}[pwndbg.gdblib.arch.endian] + {4: "I", 8: "Q"}[psize]

    for i in range(0, len(mem), step):
        candidate = mem[i : i + psize]
        if len(candidate) == psize:
            value = struct.unpack(fmt, candidate)[0]

            # Clear any flags
            value &= ~0xF

            if value < min_fast:
                continue

            # The value must be less than or equal to the max size we're looking
            # for, but still be able to reach the target address
            if value <= max_size and i + value >= max_size:
                yield i - psize
