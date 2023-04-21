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

try:
    # test address translation functions for LowMem
    min_low_pfn = int(gdb.lookup_global_symbol("min_low_pfn").value())
    max_low_pfn = int(gdb.lookup_global_symbol("max_low_pfn").value())
    pfns = [min_low_pfn, max_low_pfn]

    for pfn in pfns:
        assert kernel.virt_to_pfn(kernel.pfn_to_virt(pfn)) == pfn
        assert kernel.phys_to_pfn(kernel.pfn_to_phys(pfn)) == pfn
        assert kernel.page_to_pfn(kernel.pfn_to_page(pfn)) == pfn
        virt = kernel.pfn_to_virt(pfn)
        assert kernel.phys_to_virt(kernel.virt_to_phys(virt)) == virt
        assert kernel.page_to_virt(kernel.virt_to_page(virt)) == virt
        phys = kernel.pfn_to_phys(pfn)
        assert kernel.page_to_phys(kernel.phys_to_page(phys)) == phys
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
