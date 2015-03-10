import gdb
import pwndbg.commands
import pwndbg.color
import pwndbg.vmmap
import pwndbg.symbol
import pwndbg.regs
import pwndbg.ui
import pwndbg.disasm
import pwndbg.chain
import pwndbg.commands.telescope
import pwndbg.events


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.events.stop
def context(*args):
    if len(args) == 0:
        args = ['reg','code','stack','backtrace']

    args = [a[0] for a in args]

    print(pwndbg.color.legend())
    if 'r' in args: context_regs()
    if 'c' in args: context_code()
    if 's' in args: context_stack()
    if 'b' in args: context_backtrace()

def context_regs():
    print(pwndbg.color.blue(pwndbg.ui.banner("registers")))
    for reg in pwndbg.regs.gpr + (pwndbg.regs.frame, pwndbg.regs.stack, '$pc'):
        if reg is None:
            continue

        value = pwndbg.regs[reg]

        # Make the register stand out
        regname = pwndbg.color.bold(reg.ljust(4).upper())

        print("%s %s" % (regname, pwndbg.chain.format(value)))

def context_code():
    print(pwndbg.color.blue(pwndbg.ui.banner("code")))
    pc = pwndbg.regs.pc
    instructions = pwndbg.disasm.near(pwndbg.regs.pc, 5)

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.vmmap.find(pc)

    # Ensure screen data is always at the same spot
    for i in range(11 - len(instructions)):
        print()

    # Find all of the symbols for the addresses
    symbols = []
    for i in instructions:
        symbol = pwndbg.symbol.get(i.address)
        if symbol:
            symbol = '<%s> ' % symbol
        symbols.append(symbol)

    # Find the longest symbol name so we can adjust
    longest_sym = max(map(len, symbols))

    # Pad them all out
    for i,s in enumerate(symbols):
        symbols[i] = s.ljust(longest_sym)

    # Print out each instruction
    for i,s in zip(instructions, symbols):
        asm    = pwndbg.disasm.color(i)
        prefix = ' =>' if i.address == pc else '   '
        print(prefix, s + hex(i.address), asm)

def context_stack():
    print(pwndbg.color.blue(pwndbg.ui.banner("stack")))
    pwndbg.commands.telescope.telescope(pwndbg.regs.sp)

def context_backtrace():
    print(pwndbg.color.blue(pwndbg.ui.banner("backtrace")))
    frame = gdb.selected_frame()
    for i in range(0,10):
        if frame:
            print(pwndbg.ui.addrsz(frame.pc()), frame.name() or '???')
            frame = frame.older()