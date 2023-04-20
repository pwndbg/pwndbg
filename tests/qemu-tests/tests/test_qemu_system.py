import traceback

import gdb

import pwndbg
import pwndbg.commands.kconfig
from pwndbg.gdblib import kernel

gdb.execute("break start_kernel")
gdb.execute("continue")

try:
    pwndbg.commands.kconfig.kconfig()
except Exception:
    traceback.print_exc()
    exit(1)

# test address translation functions
try:
    virts = [
        0x0,
        0xFFFF888000000000,
        0xFFFF888007FE0000,
        0xFFFFFFFF7FFFF000,
        0xFFFFFFFF80000000,
        0xFFFFFFFF80001000,
        0xFFFFFFFFFFFFF000,
    ]
    for virt in virts:
        assert kernel.phys_to_virt(kernel.virt_to_phys(virt)) == virt
        assert kernel.pfn_to_virt(kernel.virt_to_pfn(virt)) == virt
        assert kernel.page_to_virt(kernel.virt_to_page(virt)) == virt
        phys = kernel.virt_to_phys(virt)
        assert kernel.pfn_to_phys(kernel.phys_to_pfn(phys)) == phys
        assert kernel.page_to_phys(kernel.phys_to_page(phys)) == phys
        pfn = kernel.virt_to_pfn(virt)
        assert kernel.page_to_pfn(kernel.pfn_to_page(pfn)) == pfn
except Exception:
    traceback.print_exc()
    exit(1)


try:
    release_ver = pwndbg.gdblib.kernel.krelease()
    # release should be int tuple of form (major, minor, patch) or (major, minor)
    assert len(release_ver) >= 2
    release_str = "Linux version " + ".".join([str(x) for x in release_ver])
    assert release_str in pwndbg.gdblib.kernel.kversion()

except Exception:
    traceback.print_exc()
    exit(1)
