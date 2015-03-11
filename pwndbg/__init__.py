import gdb
import pwndbg.arch
import pwndbg.vmmap
import pwndbg.dt
import pwndbg.memory
import pwndbg.elf
import pwndbg.proc
import pwndbg.regs
import pwndbg.stack
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.hexdump
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.commands.vmmap
import pwndbg.commands.dt
import pwndbg.commands.search
import pwndbg.commands.auxv
import pwndbg.commands.windbg

prompt = pwndbg.color.red('pwn> ')
prompt = pwndbg.color.bold(prompt)

pre_commands = """
set confirm off
set verbose off
set output-radix 0x10
set prompt %s
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
""".strip() % prompt

for line in pre_commands.splitlines():
	if line:
		gdb.execute(line)

@pwndbg.memoize.reset_on_stop
def prompt_hook(*a):
    pwndbg.commands.context.context()

gdb.prompt_hook = prompt_hook
