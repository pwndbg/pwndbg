import pwndbg.regs
import pwndbg.ui
import pwndbg.symbol
import pwndbg.vmmap
import pwndbg.disasm
import pwndbg.color
import pwndbg.ida

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, to_string=False):
    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None or pc < 0x100:
        lines = pc
        pc    = None

    if pc is None:
        pc = pwndbg.regs.pc
    if lines is None:
        lines = 5

    pc    = int(pc)
    lines = int(lines)

    result = []
    instructions = pwndbg.disasm.near(pwndbg.regs.pc, lines)

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.vmmap.find(pc)

    # Find all of the symbols for the addresses
    symbols = []
    for i in instructions:
        symbol = pwndbg.symbol.get(i.address)
        if symbol:
            symbol = '<%s> ' % symbol
        symbols.append(symbol)

    # Find the longest symbol name so we can adjust
    if symbols:
        longest_sym = max(map(len, symbols))
    else:
        longest_sym = ''

    # Pad them all out
    for i,s in enumerate(symbols):
        symbols[i] = s.ljust(longest_sym)

    # Print out each instruction
    for i,s in zip(instructions, symbols):
        asm    = pwndbg.disasm.color(i)
        prefix = ' =>' if i.address == pc else '   '

        pre = pwndbg.ida.Anterior(i.address)
        if pre:
            result.append(pwndbg.color.bold(pre))

        line   = ' '.join((prefix, s + hex(i.address), asm))
        result.append(line)

    if not to_string:
        print('\n'.join(result))

    return result