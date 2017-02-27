#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

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
import pwndbg.commands.checksec
import pwndbg.commands.config
import pwndbg.commands.context
import pwndbg.commands.cpsr
import pwndbg.commands.dt
import pwndbg.commands.dumpargs
import pwndbg.commands.elf
import pwndbg.commands.gdbinit
import pwndbg.commands.heap
import pwndbg.commands.hexdump
import pwndbg.commands.ida
import pwndbg.commands.misc
import pwndbg.commands.next
import pwndbg.commands.peda
import pwndbg.commands.procinfo
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
import pwndbg.commands.vmmap
import pwndbg.commands.windbg
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
import pwndbg.heap
import pwndbg.inthook
import pwndbg.memory
import pwndbg.net
import pwndbg.proc
import pwndbg.prompt
import pwndbg.regs
import pwndbg.server
import pwndbg.stack
import pwndbg.stdio
import pwndbg.typeinfo
import pwndbg.vmmap

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
'compat',
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

prompt = "pwndbg> "
prompt = "\x02" + prompt + "\x01" # STX + prompt + SOH
prompt = pwndbg.color.red(prompt)
prompt = pwndbg.color.bold(prompt)
prompt = "\x01" + prompt + "\x02" # SOH + prompt + STX

pre_commands = """
set confirm off
set verbose off
set prompt %s
set height 0
set history expansion on
set history save on
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width 0
set print elements 15
handle SIGALRM nostop print nopass
handle SIGBUS  stop   print nopass
handle SIGPIPE nostop print nopass
handle SIGSEGV stop   print nopass
""".strip() % prompt

for line in pre_commands.strip().splitlines():
    gdb.execute(line)

# This may throw an exception, see pwndbg/pwndbg#27
try:
    gdb.execute("set disassembly-flavor intel")
except gdb.error:
    pass
