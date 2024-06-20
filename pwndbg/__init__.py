from __future__ import annotations

import signal

import gdb

# isort: off
from pwndbg.config import config as config
import pwndbg.config as config_mod
# isort: on

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib
from pwndbg.commands import load_commands
from pwndbg.gdblib import load_gdblib

load_commands()
load_gdblib()

# TODO: Convert these to gdblib modules and remove this
try:
    import pwndbg.gdblib.disasm
    import pwndbg.gdblib.disasm.aarch64
    import pwndbg.gdblib.disasm.arm
    import pwndbg.gdblib.disasm.jump
    import pwndbg.gdblib.disasm.mips
    import pwndbg.gdblib.disasm.ppc
    import pwndbg.gdblib.disasm.riscv
    import pwndbg.gdblib.disasm.sparc
    import pwndbg.gdblib.disasm.x86
    import pwndbg.gdblib.heap
except ModuleNotFoundError:
    pass

import pwndbg.exception
import pwndbg.lib.version
import pwndbg.ui

__version__ = pwndbg.lib.version.__version__
version = __version__

from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import prompt

prompt.set_prompt()

pre_commands = f"""
set confirm off
set verbose off
set pagination off
set height 0
set history save on
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width {pwndbg.ui.get_window_size()[1]}
handle SIGALRM nostop print nopass
handle SIGBUS  stop   print nopass
handle SIGPIPE nostop print nopass
handle SIGSEGV stop   print nopass
""".strip()

# See https://github.com/pwndbg/pwndbg/issues/808
if gdb_version[0] <= 9:
    pre_commands += "\nset remote search-memory-packet off"

for line in pre_commands.strip().splitlines():
    gdb.execute(line)

# This may throw an exception, see pwndbg/pwndbg#27
try:
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    pass

# handle resize event to align width and completion
signal.signal(
    signal.SIGWINCH,
    lambda signum, frame: gdb.execute("set width %i" % pwndbg.ui.get_window_size()[1]),
)

# Reading Comment file
from pwndbg.commands import comments

comments.init()

from pwndbg.gdblib import config_mod as gdblib_config_mod

gdblib_config_mod.init_params()

from pwndbg.gdblib.prompt import show_hint

show_hint()
