"""Linux resource limit IDs, independent of the debugger host's architecture."""

from __future__ import annotations

# include/uapi/asm-generic/resource.h in the Linux kernel.
LINUX_RLIMITS: dict[str, int] = {
    "cpu": 0,
    "fsize": 1,
    "data": 2,
    "stack": 3,
    "core": 4,
    "rss": 5,
    "nproc": 6,
    "nofile": 7,
    "memlock": 8,
    "as": 9,
    "locks": 10,
    "sigpending": 11,
    "msgqueue": 12,
    "nice": 13,
    "rtprio": 14,
    "rttime": 15,
}

# arch/{mips,sparc}/include/uapi/asm/resource.h override these IDs.
_ARCH_OVERRIDES: dict[str, dict[str, int]] = {
    "mips": {"nofile": 5, "as": 6, "rss": 7, "nproc": 8, "memlock": 9},
    "sparc": {"nofile": 6, "nproc": 7},
}


def resource_id(resource: str, arch: str) -> int:
    return _ARCH_OVERRIDES.get(arch, {}).get(resource, LINUX_RLIMITS[resource])


def infinity(arch: str, ptrsize: int) -> int:
    # MIPS32 and SPARC32 preserve the historical signed-long maximum.
    if arch in ("mips", "sparc") and ptrsize == 4:
        return 0x7FFFFFFF
    return (1 << (ptrsize * 8)) - 1
