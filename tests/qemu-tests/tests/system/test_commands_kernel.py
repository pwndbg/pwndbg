from __future__ import annotations

import gdb
import pytest

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.slab
import pwndbg.dbg


def test_command_kchecksec():
    res = gdb.execute("kchecksec", to_string=True)
    assert res != ""  # for F841 warning
    # TODO: do something with res


def test_command_kcmdline():
    res = gdb.execute("kcmdline", to_string=True)
    assert res != ""  # for F841 warning
    # TODO: do something with res


def test_command_kconfig():
    res = gdb.execute("kconfig", to_string=True)
    assert "CONFIG_IKCONFIG = y" in res

    res = gdb.execute("kconfig IKCONFIG", to_string=True)
    assert "CONFIG_IKCONFIG = y" in res


def test_command_kversion():
    res = gdb.execute("kversion", to_string=True)
    assert "Linux version" in res


def test_command_slab_list():
    if not pwndbg.aglib.kernel.has_debug_syms():
        res = gdb.execute("slab list", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("slab list", to_string=True)
    assert "kmalloc" in res


def test_command_slab_info():
    if not pwndbg.aglib.kernel.has_debug_syms():
        res = gdb.execute("slab info kmalloc-512", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    for cache in pwndbg.aglib.kernel.slab.caches():
        cache_name = cache.name
        res = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        assert cache_name in res
        assert "Freelist" in res
        for cpu in range(pwndbg.aglib.kernel.nproc()):
            assert f"[CPU {cpu}]" in res

    res = gdb.execute("slab info -v does_not_exit", to_string=True)
    assert "not found" in res


def test_command_slab_contains():
    if not pwndbg.aglib.kernel.has_debug_syms():
        res = gdb.execute("slab contains 0x123", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    # retrieve a valid slab object address (first address from freelist)
    addr, slab_cache = get_slab_object_address()

    res = gdb.execute(f"slab contains {addr}", to_string=True)
    assert f"{addr} @ {slab_cache}" in res


@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["x86", "x86-64"],
    reason="function page_offset is only implemented for x86",
)
def test_x64_extra_registers_under_kernel_mode():
    res = gdb.execute("context", to_string=True)
    for reg in ["cr0", "cr3", "cr4", "fs_base", "gs_base", "efer", "ss", "cs"]:
        assert reg.upper() in res
    # those are the most important ones, and their presence should indicate it's working as intended
    for flag in ["smep", "smap", "wp"]:
        assert flag in res or flag.upper() in res


def get_slab_object_address():
    """helper function to get the address of some kmalloc slab object
    and the associated slab cache name"""
    import re

    caches = pwndbg.aglib.kernel.slab.caches()
    for cache in caches:
        cache_name = cache.name
        info = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
        info = ansi_escape.sub("", info)
        matches = re.findall(r"- \[0x[0-9a-fA-F\-]{2}\] (0x[0-9a-fA-F]+)", info)
        if len(matches) > 0:
            return (matches[0], cache_name)
    raise ValueError("Could not find any slab objects")


@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["x86", "x86-64"],
    reason="Unsupported architecture: msr tests only work on x86 and x86-64",
)
def test_command_msr_read():
    msr_lstar_literal = int(gdb.execute("msr MSR_LSTAR", to_string=True).split(":\t")[1], 16)
    msr_lstar = int(gdb.execute("msr 0xc0000082", to_string=True).split(":\t")[1], 16)
    assert msr_lstar == msr_lstar_literal


@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["x86", "x86-64"],
    reason="Unsupported architecture: msr tests only work on x86 and x86-64",
)
def test_command_msr_write():
    prev_msr_lstar = int(gdb.execute("msr MSR_LSTAR", to_string=True).split(":\t")[1], 16)

    new_val = 0x4141414142424242
    gdb.execute(f"msr MSR_LSTAR -w {new_val}")
    new_msr_lstar = int(gdb.execute("msr 0xc0000082", to_string=True).split(":\t")[1], 16)
    assert new_msr_lstar == new_val
    gdb.execute(f"msr MSR_LSTAR -w {prev_msr_lstar}")


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["x86", "x86-64"],
    reason="function page_offset is only implemented for x86",
)
def test_command_buddydump():
    res = gdb.execute("buddydump", to_string=True)
    assert (
        "Order" in res and "Zone" in res and ("per_cpu_pageset" in res or "free_area" in res)
    ) or res == "WARNING: Symbol 'node_data' not found\n"
