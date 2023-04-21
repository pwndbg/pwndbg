import gdb

import pwndbg

gdb.execute("break break_here")
assert pwndbg.gdblib.symbol.address("main") == 0x5500000A1C
gdb.execute("continue")

gdb.execute("argv", to_string=True)
assert gdb.execute("argc", to_string=True) == 1
gdb.execute("auxv", to_string=True)
assert gdb.execute("cpsr", to_string=True) == "cpsr 0x60000000 [ n Z C v q pan il d a i f el sp ]"
gdb.execute("context", to_string=True)
gdb.execute("hexdump", to_string=True)
gdb.execute("telescope", to_string=True)

# TODO: Broken
gdb.execute("retaddr", to_string=True)

# Broken
gdb.execute("procinfo", to_string=True)

# Broken
gdb.execute("vmmap", to_string=True)

gdb.execute("piebase", to_string=True)

gdb.execute("nextret", to_string=True)
