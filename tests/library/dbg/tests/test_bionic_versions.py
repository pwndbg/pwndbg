"""
Bionic (Android libc) multi-API harness: static NDK binaries (one per API level, from
Dockerfile.bionic-test-libs) run under gdb on plain Linux, no emulator. Asserts each
binary runs and its .note.android.ident API matches; pwndbg's own detection (which() ==
UNKNOWN; there is no bionic provider yet) is in test_bionic_libc_detection below.
"""

from __future__ import annotations

import platform
import struct
from pathlib import Path

import pytest
from elftools.elf.elffile import ELFFile

from ....host import Controller
from . import bionic_apis
from . import get_binary
from . import launch_to
from . import pwndbg_test

BIONIC_APIS = [int(a) for a in bionic_apis()]
assert BIONIC_APIS, "no API levels parsed from Dockerfile.bionic-test-libs"


def _read_android_api(binary: Path) -> int:
    """Read android_api from a binary's .note.android.ident note. The descriptor's first
    word (LE) is the build-target API level; we parse the raw bytes so it works across
    pyelftools versions (which don't special-case this Android note)."""
    with open(binary, "rb") as f:
        elf = ELFFile(f)
        section = elf.get_section_by_name(".note.android.ident")
        assert section is not None, f".note.android.ident missing from {binary}"
        data = section.data()

    # ELF note: n_namesz/n_descsz/n_type (3x u32 LE), name padded to 4, then the
    # descriptor whose first word is android_api.
    n_namesz, _n_descsz, _n_type = struct.unpack_from("<III", data, 0)
    desc_off = 12 + ((n_namesz + 3) & ~3)
    (android_api,) = struct.unpack_from("<I", data, desc_off)
    return int(android_api)


@pytest.mark.parametrize("api", BIONIC_APIS, ids=[str(a) for a in BIONIC_APIS])
@pwndbg_test
async def test_bionic_version(ctrl: Controller, api: int) -> None:
    """The static bionic binary for `api` runs under gdb and its
    .note.android.ident android_api field equals `api`."""
    binary = get_binary(f"bionics/{api}/bionic_probe.bionic-{api}-static.out")
    if not binary.exists():
        pytest.skip(f"bionic API {api} test binary not available")
    # Checked before launching: the probes are prebuilt x86-64 ELFs, so on another
    # arch the launch itself fails with an exec format error before any skip.
    if platform.machine() != "x86_64":
        pytest.skip("bionic tests are x86-64 only (prebuilt x86-64 probes)")

    await ctrl.disable_debuginfod()
    # Reaching break_here proves the static bionic binary started and ran under
    # gdb on plain Linux, no emulator.
    await launch_to(ctrl, binary, "break_here")

    note_api = _read_android_api(binary)
    assert note_api == api, f"expected android_api {api}, got {note_api} from .note.android.ident"


@pytest.mark.parametrize("api", BIONIC_APIS, ids=[str(a) for a in BIONIC_APIS])
@pwndbg_test
async def test_bionic_libc_detection(ctrl: Controller, api: int) -> None:
    """What pwndbg's libc detection does on a static bionic binary today: there is no
    bionic provider, so which() is UNKNOWN (and must not crash), version() is (-1, -1),
    and has_debug_info() is False. Turning these into a real BIONIC assertion is the
    separate Android-Debugging project's job."""
    binary = get_binary(f"bionics/{api}/bionic_probe.bionic-{api}-static.out")
    if not binary.exists():
        pytest.skip(f"bionic API {api} test binary not available")
    if platform.machine() != "x86_64":
        pytest.skip("bionic tests are x86-64 only (prebuilt x86-64 probes)")

    import pwndbg.libc

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.UNKNOWN
    assert pwndbg.libc.version() == (-1, -1)
    assert pwndbg.libc.has_debug_info() is False
