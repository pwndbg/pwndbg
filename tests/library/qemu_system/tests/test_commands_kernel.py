from __future__ import annotations

import functools
import random
import re
from collections.abc import Callable
from typing import Any
from typing import TypeVar

import gdb
import pytest
from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.slab
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.vmmap
import pwndbg.color

P = ParamSpec("P")
T = TypeVar("T")


def KernelTest(func: Callable[P, T]) -> Callable[P, T | None]:
    @functools.wraps(func)
    def wrapper(*a: P.args, **kw: P.kwargs) -> T | None:
        pwndbg.color._disable_colors_trigger()
        # TODO: trigger NEW_OBJFILE event instead
        return func(*a, **kw)

    return wrapper


@KernelTest
def test_command_kchecksec() -> None:
    res = gdb.execute("kchecksec", to_string=True)
    assert res != ""  # for F841 warning
    # TODO: do something with res


@KernelTest
def test_command_kcmdline() -> None:
    res = gdb.execute("kcmdline", to_string=True)
    assert res != ""  # for F841 warning
    # TODO: do something with res


@KernelTest
def test_command_kconfig() -> None:
    res = gdb.execute("kconfig", to_string=True)
    assert " = y" in res


@KernelTest
def test_command_kdmesg() -> None:
    if not pwndbg.aglib.kernel.has_debug_info():
        res = gdb.execute("kdmesg", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("kdmesg", to_string=True)
    assert "Linux version" in res

    res = gdb.execute("kdmesg -T", to_string=True)
    ctime_regex = r"(Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}"
    assert (
        any(re.search(ctime_regex, line) for line in res.splitlines())
        or "`struct tk_data` is not defined in the current debug symbols." in res
    )


@KernelTest
def test_command_kmod() -> None:
    if not pwndbg.aglib.kernel.has_debug_symbols("find_module_all"):
        res = gdb.execute("kmod", to_string=True)
        return

    res = gdb.execute("kmod", to_string=True)
    assert "Kernel modules address found at" in res or "The modules symbol was not found." in res


@KernelTest
def test_command_ksyscalls() -> None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        res = gdb.execute("ksyscalls", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("ksyscalls", to_string=True)
    assert "entries found at" in res or "sys_call_table symbol was not found" in res


@KernelTest
def test_command_ktask() -> None:
    res = gdb.execute("ktask", to_string=True)
    assert "task @" in res
    p = re.compile(r"\[pid (\d)+\]")
    userpid = None
    for line in res.splitlines():
        match = re.search(p, line)
        if not match:
            continue
        if "user task" in line:
            userpid = int(match.group(1))
            break
    else:
        userpid = 1
    res = gdb.execute("kcurrent", to_string=True)
    assert "task @" in res
    res = gdb.execute("kstack", to_string=True)
    assert "canary =" in res
    res = gdb.execute("knamespace", to_string=True)
    assert "_ns" in res
    res = gdb.execute(f"kcurrent --set {userpid}", to_string=True)
    if "not found" not in res and "user task" in res:
        res = gdb.execute("kfile", to_string=True)
        assert "[fileno 001]" in res


@KernelTest
def test_command_kversion() -> None:
    res = gdb.execute("kversion", to_string=True)
    assert "Linux version" in res


@KernelTest
def test_command_slab_list() -> None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        res = gdb.execute("slab list", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("slab list", to_string=True)
    assert "kmalloc" in res


@KernelTest
def test_command_slab_info() -> None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        res = gdb.execute("slab info kmalloc-512", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return
    for cache in pwndbg.aglib.kernel.slab.caches():
        cache_name = cache.name
        res = gdb.execute(f"slab info {cache_name}", to_string=True)
        assert cache_name in res
        assert "Freelist" in res
        for cpu in range(pwndbg.aglib.kernel.nproc()):
            assert f"[CPU {cpu}]" in res

    res = gdb.execute("slab info -v does_not_exit", to_string=True)
    assert "not found" in res


@KernelTest
def test_command_slab_contains() -> None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        res = gdb.execute("slab contains 0x123", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    pwndbg.aglib.kernel.slab.recover_slab_typeinfo()
    # retrieve a valid slab object address (first address from freelist)
    addrs, slab_cache = get_slab_object_address()
    addr = addrs[0]

    res = gdb.execute(f"slab contains {addr}", to_string=True)
    assert f"{addr} @ {slab_cache}" in res
    assert "cpu" in res or "node" in res
    res2 = gdb.execute(f"slab contains {int(addr, 16) + 1}", to_string=True)
    assert res == res2, "unaligned object address test failed"


@KernelTest
@pytest.mark.skipif(
    pwndbg.aglib.arch.name not in ["i386", "x86-64"],
    reason="function page_offset is only implemented for x86",
)
def test_x64_extra_registers_under_kernel_mode() -> None:
    res = gdb.execute("context", to_string=True)
    for reg in ["cr0", "cr3", "cr4", "fs_base", "gs_base", "efer", "ss", "cs"]:
        assert reg.upper() in res
    # those are the most important ones, and their presence should indicate it's working as intended
    for flag in ["smep", "smap", "wp"]:
        assert flag in res or flag.upper() in res


def get_slab_object_address() -> tuple[list[Any], str]:
    """helper function to get the address of some kmalloc slab object
    and the associated slab cache name"""
    caches = pwndbg.aglib.kernel.slab.caches()
    for cache in caches:
        cache_name = cache.name
        info = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        matches = re.findall(r"- \[0x[0-9a-fA-F\-]{2}\] (0x[0-9a-fA-F]+)", info)
        if len(matches) > 0:
            return (matches, cache_name)
    raise ValueError("Could not find any slab objects")


## NOTE: `msr` command is broken sometimes. It break CI alot of times. There is deadlock in our `exec_shellcode` func.
# @pytest.mark.skipif(
#     pwndbg.aglib.arch.name not in ["i386", "x86-64"],
#     reason="Unsupported architecture: msr tests only work on x86 and x86-64",
# )
# def test_command_msr_read():
#     msr_lstar_literal = int(gdb.execute("msr MSR_LSTAR", to_string=True).split(":\t")[1], 16)
#     msr_lstar = int(gdb.execute("msr 0xc0000082", to_string=True).split(":\t")[1], 16)
#     assert msr_lstar == msr_lstar_literal
#
#
# @pytest.mark.skipif(
#     pwndbg.aglib.arch.name not in ["i386", "x86-64"],
#     reason="Unsupported architecture: msr tests only work on x86 and x86-64",
# )
# def test_command_msr_write():
#     prev_msr_lstar = int(gdb.execute("msr MSR_LSTAR", to_string=True).split(":\t")[1], 16)
#
#     new_val = 0x4141414142424242
#     gdb.execute(f"msr MSR_LSTAR -w {new_val}")
#     new_msr_lstar = int(gdb.execute("msr 0xc0000082", to_string=True).split(":\t")[1], 16)
#     assert new_msr_lstar == new_val
#     gdb.execute(f"msr MSR_LSTAR -w {prev_msr_lstar}")


@KernelTest
def test_command_kernel_vmmap() -> None:
    res = gdb.execute("vmmap", to_string=True)
    assert all(
        key in res
        for key in (
            "vmalloc",
            "fixmap",
            "physmap",
            "vmemmap",
            "kernel [.text]",
            "kernel [.bss]",
        )
    )


def get_buddy_freelist_elements(out) -> list[tuple[int, int]]:
    out = pwndbg.color.strip(out)
    result = []
    for e in re.findall(r"\[0x[0-9a-fA-F\-]{2}\] (0x[0-9a-fA-F]{16} \[0x[0-9a-fA-F]{16}\])", out):
        vaddr = int(e[0], 16)
        page = int(e[1].strip("[]"), 16)
        result.append((vaddr, page))
    return result


@KernelTest
@pytest.mark.skipif(
    not pwndbg.aglib.kernel.has_debug_symbols(), reason="test requires debug symbols"
)
def test_command_buddydump() -> None:
    res = gdb.execute("buddydump", to_string=True)
    NOFREEPAGE = "No free pages with specified filters found.\n"
    if res in ("WARNING: Symbol 'node_data' not found\n", NOFREEPAGE):
        return
    # this indicates the buddy allocator contains at least one entry
    assert "order" in res and "zone" in res and ("per_cpu_pageset" in res or "free_area" in res)

    # find the starting addresses of all entries within the freelists
    matches = get_buddy_freelist_elements(res)
    for i in range(len(matches)):
        vaddr, page = matches[i]
        res = gdb.execute(f"bud -f {hex(vaddr + random.randint(0, 0x1000 - 1))}", to_string=True)
        _matches = get_buddy_freelist_elements(res)
        # asserting `bud -f` behaviour -- should be able to find the corresponding entry to an address
        # even if the address is not aligned
        assert len(_matches) == 1 and _matches[i][0] == vaddr
        assert page == pwndbg.aglib.kernel.virt_to_page(vaddr)

    # nonexistent node index should not contain any entries
    no_output = gdb.execute("buddydump -n 10", to_string=True)
    assert NOFREEPAGE == no_output

    # below checks are for filters
    # for example, if a zone name is specified, other zones should not be present
    filter_res = gdb.execute("bud -z DMA", to_string=True)
    for name in ["DMA32", "Normal", "HighMem", "Movable", "Device"]:
        assert f"zone {name.lower()}" not in filter_res
    filter_res = gdb.execute("bud -m Unmovable", to_string=True)
    for name in ["Movable", "Reclaimable", "HighAtomic", "CMA", "Isolate"]:
        assert f"- {name.lower()}" not in filter_res
    filter_res = gdb.execute("bud -o 1", to_string=True)
    for i in range(11):
        if i == 1:
            continue
        assert f"order {i}" not in filter_res
    filter_res = gdb.execute("bud -c 0", to_string=True)
    for i in range(1, pwndbg.aglib.kernel.nproc()):
        assert f"cpu #{i}" not in filter_res
    filter_res = gdb.execute("bud -n 0", to_string=True)
    for i in range(1, pwndbg.aglib.kernel.num_numa_nodes()):
        assert f"node #{i}" not in filter_res
    filter_res = gdb.execute("bud -p", to_string=True)
    assert "free_area" not in filter_res


def check_0x100_bytes(address, physmap_addr):
    # compare the first 0x100 bytes of the page (e.g. first kernel image page) with its physmap conterpart
    expected = pwndbg.aglib.memory.read(address, 0x100)
    actual = pwndbg.aglib.memory.read(physmap_addr, 0x100)
    assert all(expected[i] == actual[i] for i in range(0x100))


@KernelTest
def test_command_pagewalk() -> None:
    address = pwndbg.aglib.kernel.kbase()
    if address is None:
        pages = pwndbg.aglib.vmmap.get()
        address = pages[0].start
    res = gdb.execute(f"pagewalk {hex(address)}", to_string=True)
    assert any(
        name in res
        for name in (
            "PMD",  # Page Size is only set for PMDe or PTe
            "L1",
            "L3",
        )
    )
    res = res.splitlines()[-1]
    match = re.findall(r"0x[0-9a-fA-F]{16}", res)[0]
    physmap_addr = int(match, 16)
    check_0x100_bytes(address, physmap_addr)
    # make sure that when using cr3 for pgd, it still works
    pgd_ptr = "$cr3"
    if pwndbg.aglib.arch.name == "aarch64":
        if pwndbg.aglib.memory.is_kernel(address):
            pgd_ptr = pwndbg.aglib.regs.read_reg("TTBR1_EL1")
        else:
            pgd_ptr = pwndbg.aglib.regs.read_reg("TTBR0_EL1")
    res2 = gdb.execute(f"pagewalk {hex(address)} --pgd {pgd_ptr}", to_string=True).splitlines()[-1]
    assert res == res2
    # test non nonexistent address
    res = gdb.execute("pagewalk 0", to_string=True)
    assert res.splitlines()[-1] == "address is not mapped"


@KernelTest
@pytest.mark.skipif(
    not pwndbg.aglib.kernel.has_debug_symbols(), reason="test requires debug symbols"
)
def test_command_paging() -> None:
    def test_command_paging_helper(pagetype, addr):
        out = gdb.execute(f"v2p {addr}", to_string=True)
        # pagetype should be correct
        assert pagetype in out
        page = int(out.splitlines()[1].split()[2], 16)
        physmap_addr = int(out.splitlines()[0].split()[-1], 16)
        physmap_addr = pwndbg.aglib.kernel.phys_to_virt(physmap_addr)
        # the first 0x100 bytes of the resolved address should match the original
        check_0x100_bytes(addr, physmap_addr)
        phys_addr = pwndbg.aglib.kernel.virt_to_phys(physmap_addr)
        out = gdb.execute(f"p2v {phys_addr}", to_string=True)
        # the virtual address should be the physmap address
        assert physmap_addr == int(out.splitlines()[0].split()[-1], 16)
        out = gdb.execute(f"pageinfo {page}", to_string=True)
        # the virtual address should be the physmap address
        assert physmap_addr == int(out.splitlines()[0].split()[-1], 16)

    pi = pwndbg.aglib.kernel.arch_paginginfo()
    assert pi is not None
    # kbase, slab, buddy, vmemmap
    kbase = pwndbg.aglib.kernel.kbase()
    test_command_paging_helper("initialized", kbase)
    vmemmap = pi.vmemmap
    if pwndbg.aglib.arch.name == "aarch64":
        vmemmap += pi.ram_phys_start >> (pi.page_shift - pi.STRUCT_PAGE_SHIFT)
    test_command_paging_helper("initialized", vmemmap)
    res = gdb.execute("buddydump", to_string=True)
    matches = get_buddy_freelist_elements(res)
    if len(matches) > 0 and "free_area" in res:  # only pages in free_area is marked "buddy"
        test_command_paging_helper("buddy", matches[-1][0])

    krelease = pwndbg.aglib.kernel.krelease()
    assert krelease is not None
    if krelease >= (6, 10):
        # the slab marker is only added after v6.10
        res = gdb.execute("slab info -v -p kmalloc-32", to_string=True)
        matches = get_buddy_freelist_elements(res)
        if len(matches) > 0:
            test_command_paging_helper("slab", matches[-1][0])
        res = gdb.execute(f"pagewalk {kbase}", to_string=True)
