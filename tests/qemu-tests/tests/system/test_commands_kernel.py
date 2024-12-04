from __future__ import annotations

import gdb

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


def get_slab_object_address():
    """helper function to get the address of some kmalloc slab object
    and the associated slab cache name"""
    import re

    caches = pwndbg.aglib.kernel.slab.caches()
    for cache in caches:
        cache_name = cache.name
        info = gdb.execute(f"slab info -v {cache_name}", to_string=True)
        matches = re.findall(r"- (0x[0-9a-fA-F]+)", info)
        if len(matches) > 0:
            return (matches[0], cache_name)
    raise ValueError("Could not find any slab objects")
