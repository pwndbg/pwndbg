from __future__ import annotations

import random
import re

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
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
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
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
    reason="Unsupported architecture: msr tests only work on x86 and x86-64",
)
def test_command_msr_read():
    msr_lstar_literal = int(gdb.execute("msr MSR_LSTAR", to_string=True).split(":\t")[1], 16)
    msr_lstar = int(gdb.execute("msr 0xc0000082", to_string=True).split(":\t")[1], 16)
    assert msr_lstar == msr_lstar_literal


@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
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
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
    reason="function page_offset is only implemented for x86",
)
def test_command_buddydump():
    res = gdb.execute("buddydump", to_string=True)
    NOFREEPAGE = "No free pages with specified filters found.\n"
    if res == "WARNING: Symbol 'node_data' not found\n" or NOFREEPAGE == res:
        return
    # this indicates the buddy allocator contains at least one entry
    assert "Order" in res and "Zone" in res and ("per_cpu_pageset" in res or "free_area" in res)

    ansi_escape = re.compile(r"\x1b\[[0-9;]*m")
    res = ansi_escape.sub("", res)
    # find the starting addresses of all entries within the freelists
    matches = re.findall(r"\[0x[0-9a-fA-F\-]{2}\] (0x[0-9a-fA-F]{16})", res)
    for i in range(0, len(matches), 20):
        # check every 20 elements so tests do not take too long
        match = int(matches[i], 16)
        res = gdb.execute(f"bud -f {hex(match + random.randint(0, 0x1000 - 1))}", to_string=True)
        res = ansi_escape.sub("", res)
        _matches = re.findall(r"\[0x[0-9a-fA-F\-]{2}\] (0x[0-9a-fA-F]{16})", res)
        # asserting `bud -f` behaviour -- should be able to find the corresponding entry to an address
        # even if the address is not aligned
        assert len(_matches) == 1 and int(_matches[0], 16) == match

    # nonexistent node index should not contain any entries
    no_output = gdb.execute("buddydump -n 10", to_string=True)
    assert NOFREEPAGE == no_output

    # below checks are for filters
    # for example, if a zone name is specified, other zones should not be present
    filter_res = gdb.execute("bud -z DMA", to_string=True)
    for name in ["DMA32", "Normal", "HighMem", "Movable", "Device"]:
        assert f"Zone {name}" not in filter_res
    filter_res = gdb.execute("bud -m Unmovable", to_string=True)
    for name in ["Movable", "Reclaimable", "HighAtomic", "CMA", "Isolate"]:
        assert f"- {name}" not in filter_res
    filter_res = gdb.execute("bud -o 1", to_string=True)
    for i in range(11):
        if i == 1:
            continue
        assert f"Order {i}" not in filter_res
    filter_res = gdb.execute("bud -p", to_string=True)
    assert "free_area" not in filter_res


@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
    reason="pagewalk is only fully implemented for x86 (partially relies on cr3)",
)
def test_command_pagewalk():
    address = pwndbg.aglib.kernel.kbase()
    if address is None:
        # no kbase? fine
        pages = pwndbg.aglib.vmmap.get()
        address = pages[0].start
    if not pwndbg.aglib.kernel.has_debug_syms():
        # even if no debug symbols, still gracefully handle it
        res = gdb.execute(f"pagewalk {hex(address)}")
        # now let's guess the phymap base and should work as intended
        res = gdb.execute("set guess-physmap on")
    res = gdb.execute(f"pagewalk {hex(address)}", to_string=True)
    assert "PMD" in res  # Page Size is only set for PMDe or PTe
    res = res.splitlines()[-1]
    match = re.findall(r"0x[0-9a-fA-F]{16}", res)[0]
    physmap_addr = int(match, 16)
    # compare the first 0x100 bytes of the page (e.g. first kernel image page) with its physmap conterpart
    expected = pwndbg.aglib.memory.read(address, 0x100)
    actual = pwndbg.aglib.memory.read(physmap_addr, 0x100)
    assert all(expected[i] == actual[i] for i in range(0x100))
    # make sure that when using cr3 for pgd, it still works
    res2 = gdb.execute(f"pagewalk {hex(address)} --pgd $cr3", to_string=True).splitlines()[-1]
    assert res == res2
    # test non nonexistent address
    res = gdb.execute("pagewalk 0", to_string=True)
    assert res.splitlines()[-1] == "address is not mapped"
