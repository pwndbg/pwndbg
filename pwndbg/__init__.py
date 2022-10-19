import signal

import gdb

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib
from pwndbg.commands import load_commands
from pwndbg.gdblib import load_gdblib

load_commands()
load_gdblib()

# TODO: Convert these to gdblib modules and remove this
try:
    import pwndbg.disasm
    import pwndbg.disasm.arm
    import pwndbg.disasm.jump
    import pwndbg.disasm.mips
    import pwndbg.disasm.ppc
    import pwndbg.disasm.sparc
    import pwndbg.disasm.x86
    import pwndbg.heap
except ModuleNotFoundError:
    pass

import pwndbg.exception
import pwndbg.lib.version
import pwndbg.ui

__version__ = pwndbg.lib.version.__version__
version = __version__

__all__ = [
    "arch",
    "auxv",
    "chain",
    "color",
    "disasm",
    "dt",
    "elf",
    "enhance",
    "events",
    "file",
    "function",
    "heap",
    "hexdump",
    "ida",
    "info",
    "leakfind",
    "linkmap",
    "malloc",
    "memoize",
    "memory",
    "p2p",
    "proc",
    "regs",
    "remote",
    "search",
    "stack",
    "strings",
    "symbol",
    "typeinfo",
    "ui",
    "vmmap",
]

from pwndbg.gdblib import prompt

prompt.set_prompt()

pre_commands = """
set confirm off
set verbose off
set pagination off
set height 0
set history save on
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width %i
handle SIGALRM nostop print nopass
handle SIGBUS  stop   print nopass
handle SIGPIPE nostop print nopass
handle SIGSEGV stop   print nopass
""".strip() % (
    pwndbg.ui.get_window_size()[1]
)

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

from pwndbg.gdblib import config_mod

config_mod.init_params()
