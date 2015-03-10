import gdb
import pwndbg.arch
import pwndbg.vmmap
import pwndbg.dt
import pwndbg.memory
import pwndbg.elf
import pwndbg.proc
import pwndbg.regs
import pwndbg.stack
import pwndbg.commands
import pwndbg.commands.hexdump
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.commands.vmmap
import pwndbg.commands.dt


pre_commands = """
set confirm off
set verbose off
set output-radix 0x10
set prompt geef> 
set height 0
set history expansion on
set history save on
set disassembly-flavor intel
set follow-fork-mode child
set backtrace past-main on
set step-mode on
set print pretty on
set width 0
set print elements 15
set input-radix 16
handle SIGALRM print nopass
handle SIGSEGV stop print nopass
""".strip()

for line in pre_commands.splitlines():
	if line: 
		gdb.execute(line)
