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
