import traceback

import gdb

import pwndbg
import pwndbg.commands.kconfig

gdb.execute("break start_kernel")
gdb.execute("continue")

try:
    pwndbg.commands.kconfig.kconfig()
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
