"""
pwndbg musl detection across multiple musl versions: binaries linked (static + dynamic)
against per-version musl libcs from Dockerfile.musl-test-libs. The musl provider already
exists; these feed it per-version binaries and assert the detected version.
"""

from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import musl_test_versions
from . import pwndbg_test

# Versions parsed from Dockerfile.musl-test-libs (its build-<ver> stages) so the
# list lives in one place.
MUSL_VERSIONS = musl_test_versions()
assert MUSL_VERSIONS, "no musl versions parsed from Dockerfile.musl-test-libs"

# mallocng arrived in 1.2.1; a static binary is only fingerprintable as musl via the
# mallocng signature, so pre-1.2.1 is exercised dynamically only.
_MALLOCNG_MIN = (1, 2, 1)


def musl_ver_tuple(ver: str) -> tuple[int, ...]:
    return tuple(int(p) for p in ver.split("."))


def _version_linkages() -> list[tuple[str, str]]:
    combos: list[tuple[str, str]] = []
    for ver in MUSL_VERSIONS:
        combos.append((ver, "dynamic"))
        if musl_ver_tuple(ver) >= _MALLOCNG_MIN:
            combos.append((ver, "static"))
    return combos


_COMBOS = _version_linkages()


@pytest.mark.parametrize(
    "musl_ver,linkage", _COMBOS, ids=[f"{ver}-{linkage}" for ver, linkage in _COMBOS]
)
@pwndbg_test
async def test_musl_version_detection(ctrl: Controller, musl_ver: str, linkage: str) -> None:
    """pwndbg detects musl and resolves the exact version from a binary linked
    against that musl version."""
    binary = get_binary(f"heap_musl.musl-{musl_ver}-{linkage}.out")
    if not binary.exists():
        pytest.skip(f"musl {musl_ver} ({linkage}) test binary not available")

    import pwndbg.aglib
    import pwndbg.libc

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("musl version tests are x86-64/aarch64 only")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.MUSL
    assert pwndbg.libc.version() == musl_ver_tuple(musl_ver), (
        f"expected musl {musl_ver_tuple(musl_ver)}, detected {pwndbg.libc.version()}"
    )
