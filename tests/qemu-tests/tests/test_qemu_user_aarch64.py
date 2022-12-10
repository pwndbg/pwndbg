import gdb

import pwndbg

gdb.execute("break break_here")
print(pwndbg.gdblib.symbol.address("main"))
gdb.execute("continue")

gdb.execute("argv")
gdb.execute("argc")
gdb.execute("auxv")
gdb.execute("cpsr")
gdb.execute("context")
gdb.execute("hexdump")
gdb.execute("retaddr")
gdb.execute("piebase")
gdb.execute("telescope")
gdb.execute("procinfo")
gdb.execute("vmmap")
gdb.execute("nextret")
