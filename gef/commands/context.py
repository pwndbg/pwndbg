import gdb
import gef.commands
import gef.color
import gef.vmmap
import gef.symbol
import gef.regs
import gef.ui
import gef.disasm
import gef.chain
import gef.commands.telescope
import gef.events


@gef.commands.ParsedCommand
@gef.commands.OnlyWhenRunning
@gef.events.stop
def context(*args):
    if len(args) == 0:
        args = ['reg','code','stack','backtrace']

    args = [a[0] for a in args]

    print(gef.color.legend())
    if 'r' in args: context_regs()
    if 'c' in args: context_code()
    if 's' in args: context_stack()
    if 'b' in args: context_backtrace()

def context_regs():
    print(gef.color.blue(gef.ui.banner("registers")))
    for reg in gef.regs.gpr + (gef.regs.frame, gef.regs.stack, '$pc'):
        if reg is None:
            continue

        value = gef.regs[reg]

        # Make the register stand out
        regname = gef.color.bold(reg.ljust(4).upper())

        print("%s %s" % (regname, gef.chain.format(value)))

def context_code():
    print(gef.color.blue(gef.ui.banner("code")))
    pc = gef.regs.pc
    instructions = gef.disasm.near(gef.regs.pc, 5)

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    gef.vmmap.find(pc)

    # Ensure screen data is always at the same spot
    for i in range(11 - len(instructions)):
        print()

    # Find all of the symbols for the addresses
    symbols = []
    for i in instructions:
        symbol = gef.symbol.get(i.address)
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
        asm    = gef.disasm.color(i)
        prefix = ' =>' if i.address == pc else '   '
        print(prefix, s + hex(i.address), asm)

def context_stack():
    print(gef.color.blue(gef.ui.banner("stack")))
    gef.commands.telescope.telescope(gef.regs.sp)

def context_backtrace():
    print(gef.color.blue(gef.ui.banner("backtrace")))
    frame = gdb.selected_frame()
    for i in range(0,10):
        if frame:
            print(gef.ui.addrsz(frame.pc()), frame.name() or '???')
            frame = frame.older()