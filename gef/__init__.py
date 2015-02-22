import gdb
import gef.arch
import gef.vmmap
import gef.dt
import gef.memory
import gef.elf
import gef.proc
import gef.regs
import gef.stack
import gef.commands
import gef.commands.hexdump
import gef.commands.context
import gef.commands.telescope
import gef.commands.vmmap
import gef.commands.dt


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
