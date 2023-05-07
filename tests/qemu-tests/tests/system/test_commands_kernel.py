import gdb

import pwndbg


def test_command_kbase():
    pass  # TODO


def test_command_kchecksec():
    res = gdb.execute("kchecksec", to_string=True)
    # TODO: do something with res


def test_command_kcmdline():
    res = gdb.execute("kcmdline", to_string=True)
    # TODO: do something with res


def test_command_kconfig():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("kconfig", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("kconfig", to_string=True)
    assert "CONFIG_IKCONFIG = y" in res

    res = gdb.execute("kconfig IKCONFIG", to_string=True)
    assert "CONFIG_IKCONFIG = y" in res


def test_command_kversion():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("kversion", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("kversion", to_string=True)
    assert "Linux version" in res


def test_command_slab_list():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("slab list", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("slab list", to_string=True)
    assert "kmalloc" in res


def test_command_slab_info():
    if not pwndbg.gdblib.kernel.has_debug_syms():
        res = gdb.execute("slab info kmalloc-512", to_string=True)
        assert "may only be run when debugging a Linux kernel with debug" in res
        return

    res = gdb.execute("slab info -v kmalloc-512", to_string=True)
    assert "kmalloc-512" in res
    assert "Freelist" in res
    assert "In-Use" in res

    res = gdb.execute("slab info -v does_not_exit", to_string=True)
    assert "not found" in res
