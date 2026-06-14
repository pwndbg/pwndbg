from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import musl_test_versions
from . import pwndbg_test

MUSL_VERSIONS = musl_test_versions()
assert MUSL_VERSIONS, "no musl versions parsed from Dockerfile.musl-test-libs"

_MALLOCNG_MIN = (1, 2, 1)


def version_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(p) for p in ver.split("."))


def _version_linkages() -> list[tuple[str, str]]:
    combos: list[tuple[str, str]] = []
    for ver in MUSL_VERSIONS:
        combos.append((ver, "dynamic"))
        if version_tuple(ver) >= _MALLOCNG_MIN:
            combos.append((ver, "static"))
    return combos


_COMBOS = _version_linkages()


@pytest.mark.parametrize("musl_version,linkage", _COMBOS)
@pwndbg_test
async def test_musl_version_detection(ctrl: Controller, musl_version: str, linkage: str) -> None:
    binary = get_binary(f"heap_musl.musl-{musl_version}-{linkage}.out")
    if not binary.exists():
        pytest.skip(f"musl {musl_version} ({linkage}) test binary not available")

    import pwndbg.aglib
    import pwndbg.libc

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("musl version tests are x86-64/aarch64 only")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.MUSL
    detected = pwndbg.libc.version()
    expected = version_tuple(musl_version)
    assert detected == expected, f"Expected musl {expected}, detected {detected}"
