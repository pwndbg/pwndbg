from __future__ import annotations

# http://git.musl-libc.org/cgit/musl/tree/src/malloc/mallocng/meta.h?h=v1.2.2#n14
IB = 4  # in-band metadata size
UNIT = 16

UINT32_MASK = (1 << 32) - 1
UINT64_MASK = (1 << 64) - 1
