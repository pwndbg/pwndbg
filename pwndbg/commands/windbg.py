import gdb
import pwndbg.commands

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
