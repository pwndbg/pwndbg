import gdb
import pwndbg.commands
import pwndbg.symbol


@pwndbg.commands.ParsedCommand
def start():
    symbols = ["main",
               "_main",
               "start",
               "_start",
               "init",
               "_init",
               pwndbg.elf.entry()]

    for address in filter(bool, map(pwndbg.symbol.address, symbols)):
        if address:
            b = gdb.Breakpoint('*%#x' % address, temporary=True)
            gdb.execute('run', from_tty=False, to_string=True)
            break
    else:
        print("Could not find a good place to start :(")
