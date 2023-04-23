import pytest

import pwndbg


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="")
def test_gdblib_kernel_krelease():
    release_ver = pwndbg.gdblib.kernel.krelease()
    # release should be int tuple of form (major, minor, patch) or (major, minor)
    assert len(release_ver) >= 2
    release_str = "Linux version " + ".".join([str(x) for x in release_ver])
    assert release_str in pwndbg.gdblib.kernel.kversion()


@pytest.mark.skipif(not pwndbg.gdblib.kernel.has_debug_syms(), reason="")
def test_gdblib_kernel_is_kaslr_enabled():
    pwndbg.gdblib.kernel.is_kaslr_enabled()
