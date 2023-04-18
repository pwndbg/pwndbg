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
    # release should be int tuple of form: (major, minor, patch)
    assert len(release_ver) == 3
except Exception:
    traceback.print_exc()
    exit(1)
