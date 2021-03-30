#!/usr/bin/env python
# -*- coding: utf-8 -*-
import signal

import gdb

import pwndbg.android
import pwndbg.arch
import pwndbg.arguments
import pwndbg.argv
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.argv
import pwndbg.commands.aslr
import pwndbg.commands.auxv
import pwndbg.commands.canary
import pwndbg.commands.checksec
import pwndbg.commands.comments
import pwndbg.commands.config
import pwndbg.commands.context
import pwndbg.commands.cpsr
import pwndbg.commands.dt
import pwndbg.commands.dumpargs
import pwndbg.commands.elf
import pwndbg.commands.gdbinit
import pwndbg.commands.ghidra
import pwndbg.commands.got
import pwndbg.commands.heap
import pwndbg.commands.hexdump
import pwndbg.commands.ida
import pwndbg.commands.leakfind
import pwndbg.commands.misc
import pwndbg.commands.mprotect
import pwndbg.commands.next
import pwndbg.commands.peda
import pwndbg.commands.pie
import pwndbg.commands.probeleak
import pwndbg.commands.procinfo
import pwndbg.commands.radare2
import pwndbg.commands.reload
import pwndbg.commands.rop
import pwndbg.commands.ropper
import pwndbg.commands.search
import pwndbg.commands.segments
import pwndbg.commands.shell
import pwndbg.commands.stack
import pwndbg.commands.start
import pwndbg.commands.telescope
import pwndbg.commands.theme
import pwndbg.commands.version
import pwndbg.commands.vmmap
import pwndbg.commands.windbg
import pwndbg.commands.xinfo
import pwndbg.commands.xor
import pwndbg.constants
import pwndbg.disasm
import pwndbg.disasm.arm
import pwndbg.disasm.jump
import pwndbg.disasm.mips
import pwndbg.disasm.ppc
import pwndbg.disasm.sparc
import pwndbg.disasm.x86
import pwndbg.dt
import pwndbg.elf
import pwndbg.exception
import pwndbg.gdbutils.functions
import pwndbg.heap
import pwndbg.memory
import pwndbg.net
import pwndbg.proc
import pwndbg.prompt
import pwndbg.regs
import pwndbg.stack
import pwndbg.typeinfo
import pwndbg.ui
import pwndbg.version
import pwndbg.vmmap
import pwndbg.wrappers
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf

__version__ = pwndbg.version.__version__
version = __version__

try:
    import unicorn

    import pwndbg.emu
except:
    pass

__all__ = [
'arch',
'auxv',
'chain',
'color',
'disasm',
'dt',
'elf',
'enhance',
'events',
'file',
'function',
'heap',
'hexdump',
'ida',
'info',
'leakfind',
'linkmap',
'malloc',
'memoize',
'memory',
'proc',
'regs',
'remote',
'search',
'stack',
'strings',
'symbol',
'typeinfo',
'ui',
'vmmap'
]

pwndbg.prompt.set_prompt()

pre_commands = """
set confirm off
set verbose off
set pagination off
set height 0
set history expansion on
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
""".strip() % (pwndbg.ui.get_window_size()[1])

for line in pre_commands.strip().splitlines():
    gdb.execute(line)

# This may throw an exception, see pwndbg/pwndbg#27
try:
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    pass

# handle resize event to align width and completion
signal.signal(signal.SIGWINCH, lambda signum, frame: gdb.execute("set width %i" % pwndbg.ui.get_window_size()[1]))

# Workaround for gdb bug described in #321 ( https://github.com/pwndbg/pwndbg/issues/321 )
# More info: https://sourceware.org/bugzilla/show_bug.cgi?id=21946
# As stated on GDB's bugzilla that makes remote target search slower.
# After GDB gets the fix, we should disable this only for bugged GDB versions.
if 1:
    gdb.execute('set remote search-memory-packet off')

# Reading Comment file 
pwndbg.commands.comments.init()
