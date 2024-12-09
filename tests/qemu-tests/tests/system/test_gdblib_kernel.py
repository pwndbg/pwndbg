from __future__ import annotations

import os

import pytest

import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.kallsyms
import pwndbg.aglib.symbol
import pwndbg.dbg

ARCH = os.getenv("PWNDBG_ARCH")
KERNEL_TYPE = os.getenv("PWNDBG_KERNEL_TYPE")
KERNEL_VERSION = os.getenv("PWNDBG_KERNEL_VERSION")


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_archops_address_translation():
    # test address translation functions for LowMem
    min_low_pfn = int(pwndbg.dbg.selected_inferior().evaluate_expression("(long)min_low_pfn"))
    max_low_pfn = int(pwndbg.dbg.selected_inferior().evaluate_expression("(long)max_low_pfn"))
    pfns = [min_low_pfn, max_low_pfn]

    kernel = pwndbg.aglib.kernel
    for pfn in pfns:
        assert kernel.virt_to_pfn(kernel.pfn_to_virt(pfn)) == pfn
        assert kernel.phys_to_pfn(kernel.pfn_to_phys(pfn)) == pfn
        assert kernel.page_to_pfn(kernel.pfn_to_page(pfn)) == pfn
        virt = kernel.pfn_to_virt(pfn)
        assert kernel.phys_to_virt(kernel.virt_to_phys(virt)) == virt
        assert kernel.page_to_virt(kernel.virt_to_page(virt)) == virt
        phys = kernel.pfn_to_phys(pfn)
        assert kernel.page_to_phys(kernel.phys_to_page(phys)) == phys


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_krelease():
    release_ver = pwndbg.aglib.kernel.krelease()
    # release should be int tuple of form (major, minor, patch) or (major, minor)
    assert len(release_ver) >= 2
    release_str = "Linux version " + ".".join([str(x) for x in release_ver])
    assert release_str in pwndbg.aglib.kernel.kversion()


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_is_kaslr_enabled():
    pwndbg.aglib.kernel.is_kaslr_enabled()


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_nproc():
    # make sure no exception occurs
    pwndbg.aglib.kernel.nproc()


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_kbase():
    # newer arm/arm64 kernels reserve (_stext, _end] and other kernels reserve [_text, _end)
    # https://elixir.bootlin.com/linux/v6.8.4/source/arch/arm64/mm/init.c#L306
    base = pwndbg.aglib.kernel.kbase()
    assert base == pwndbg.aglib.symbol.lookup_symbol_addr(
        "_text"
    ) or base == pwndbg.aglib.symbol.lookup_symbol_addr("_stext")


@pytest.mark.skipif(not pwndbg.aglib.kernel.has_debug_syms(), reason="test requires debug symbols")
def test_gdblib_kernel_kallsyms():
    ks = pwndbg.aglib.kernel.kallsyms.get()
    assert ks["commit_creds"][0] == pwndbg.aglib.symbol.lookup_symbol_addr("commit_creds")
