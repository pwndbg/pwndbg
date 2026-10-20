from __future__ import annotations

import pytest

from pwndbg.lib.rlimit import infinity
from pwndbg.lib.rlimit import resource_id


@pytest.mark.parametrize(
    ("arch", "expected"),
    [
        ("x86-64", (5, 6, 7, 8, 9)),
        ("aarch64", (5, 6, 7, 8, 9)),
        ("powerpc", (5, 6, 7, 8, 9)),
        ("mips", (7, 8, 5, 9, 6)),
        ("sparc", (5, 7, 6, 8, 9)),
    ],
)
def test_architecture_specific_resource_ids(arch: str, expected: tuple[int, ...]) -> None:
    assert (
        tuple(resource_id(name, arch) for name in ("rss", "nproc", "nofile", "memlock", "as"))
        == expected
    )
    assert resource_id("cpu", arch) == 0
    assert resource_id("core", arch) == 4
    assert resource_id("rttime", arch) == 15


@pytest.mark.parametrize(
    ("arch", "ptrsize", "expected"),
    [
        ("i386", 4, 0xFFFFFFFF),
        ("x86-64", 8, 0xFFFFFFFFFFFFFFFF),
        ("mips", 4, 0x7FFFFFFF),
        ("mips", 8, 0xFFFFFFFFFFFFFFFF),
        ("sparc", 4, 0x7FFFFFFF),
        ("sparc", 8, 0xFFFFFFFFFFFFFFFF),
    ],
)
def test_infinity_uses_target_abi(arch: str, ptrsize: int, expected: int) -> None:
    assert infinity(arch, ptrsize) == expected
