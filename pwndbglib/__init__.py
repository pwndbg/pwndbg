#!/usr/bin/env python
# -*- coding: utf-8 -*-
import signal

import gdb

import pwndbglib.android
import pwndbglib.arch
import pwndbglib.arguments
import pwndbglib.argv
import pwndbglib.color
import pwndbglib.commands
import pwndbglib.commands.argv
import pwndbglib.commands.aslr
import pwndbglib.commands.auxv
import pwndbglib.commands.canary
import pwndbglib.commands.checksec
import pwndbglib.commands.comments
import pwndbglib.commands.config
import pwndbglib.commands.context
import pwndbglib.commands.cpsr
import pwndbglib.commands.dt
import pwndbglib.commands.dumpargs
import pwndbglib.commands.elf
import pwndbglib.commands.gdbinit
import pwndbglib.commands.ghidra
import pwndbglib.commands.got
import pwndbglib.commands.heap
import pwndbglib.commands.hexdump
import pwndbglib.commands.ida
import pwndbglib.commands.leakfind
import pwndbglib.commands.misc
import pwndbglib.commands.mprotect
import pwndbglib.commands.next
import pwndbglib.commands.peda
import pwndbglib.commands.pie
import pwndbglib.commands.probeleak
import pwndbglib.commands.procinfo
import pwndbglib.commands.radare2
import pwndbglib.commands.reload
import pwndbglib.commands.rop
import pwndbglib.commands.ropper
import pwndbglib.commands.search
import pwndbglib.commands.segments
import pwndbglib.commands.shell
import pwndbglib.commands.stack
import pwndbglib.commands.start
import pwndbglib.commands.telescope
import pwndbglib.commands.theme
import pwndbglib.commands.version
import pwndbglib.commands.vmmap
import pwndbglib.commands.windbg
import pwndbglib.commands.xinfo
import pwndbglib.commands.xor
import pwndbglib.constants
import pwndbglib.disasm
import pwndbglib.disasm.arm
import pwndbglib.disasm.jump
import pwndbglib.disasm.mips
import pwndbglib.disasm.ppc
import pwndbglib.disasm.sparc
import pwndbglib.disasm.x86
import pwndbglib.dt
import pwndbglib.elf
import pwndbglib.exception
import pwndbglib.gdbutils.functions
import pwndbglib.heap
import pwndbglib.memory
import pwndbglib.net
import pwndbglib.proc
import pwndbglib.prompt
import pwndbglib.regs
import pwndbglib.stack
import pwndbglib.typeinfo
import pwndbglib.ui
import pwndbglib.version
import pwndbglib.vmmap
import pwndbglib.wrappers
import pwndbglib.wrappers.checksec
import pwndbglib.wrappers.readelf

if __name__ == "__main__":
    __version__ = pwndbglib.version.__version__
    version = __version__

    try:
        import unicorn

        import pwndbglib.emu
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

    pwndbglib.prompt.set_prompt()

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
    """.strip() % (pwndbglib.ui.get_window_size()[1])

    for line in pre_commands.strip().splitlines():
        gdb.execute(line)

    # This may throw an exception, see pwndbg/pwndbg#27
    try:
        gdb.execute("set disassembly-flavor intel")
    except gdb.error:
        pass

    # handle resize event to align width and completion
    signal.signal(signal.SIGWINCH, lambda signum, frame: gdb.execute("set width %i" % pwndbglib.ui.get_window_size()[1]))

    # Workaround for gdb bug described in #321 ( https://github.com/pwndbg/pwndbg/issues/321 )
    # More info: https://sourceware.org/bugzilla/show_bug.cgi?id=21946
    # As stated on GDB's bugzilla that makes remote target search slower.
    # After GDB gets the fix, we should disable this only for bugged GDB versions.
    if 1:
        gdb.execute('set remote search-memory-packet off')

    # Reading Comment file 
    pwndbglib.commands.comments.init()
