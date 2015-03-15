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
import pwndbg.ida

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def context(*args):
    if len(args) == 0:
        args = ['reg','code','stack','backtrace']

    args = [a[0] for a in args]

    result = []

    result.append(pwndbg.color.legend())
    if 'r' in args: result.extend(context_regs())
    if 'c' in args: result.extend(context_code())
    if 's' in args: result.extend(context_stack())
    if 'b' in args: result.extend(context_backtrace())
    if 'b' in args: result.extend(context_signal())

    print('\n'.join(map(str, result)))

def context_regs():
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("registers")))
    for reg in pwndbg.regs.gpr + (pwndbg.regs.frame, pwndbg.regs.stack, '$pc'):
        if reg is None:
            continue

        value = pwndbg.regs[reg]

        # Make the register stand out
        regname = pwndbg.color.bold(reg.ljust(4).upper())

        result.append("%s %s" % (regname, pwndbg.chain.format(value)))
    return result

def context_code():
    pc = pwndbg.regs.pc
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("code")))
    instructions = pwndbg.disasm.near(pwndbg.regs.pc, 5)

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.vmmap.find(pc)

    # Ensure screen data is always at the same spot
    for i in range(11 - len(instructions)):
        result.append('')

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
    return result

def context_stack():
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("stack")))
    telescope = pwndbg.commands.telescope.telescope(pwndbg.regs.sp, to_string=True)
    if telescope:
        result.extend(telescope)
    return result

def context_backtrace():
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("backtrace")))
    this_frame    = gdb.selected_frame()
    newest_frame  = this_frame
    oldest_frame  = this_frame

    for i in range(5):
        try:
            candidate = oldest_frame.older()
        except gdb.MemoryError:
            break

        if not candidate:
            break
        oldest_frame = candidate

    for i in range(5):
        candidate = newest_frame.newer()
        if not candidate:
            break
        newest_frame = candidate

    frame = newest_frame
    i     = 0
    while True:
        prefix = '> ' if frame == this_frame else '  '
        line   = map(str, (prefix, 'f', i, pwndbg.ui.addrsz(frame.pc()), frame.name() or '???'))
        line   = ' '.join(line)
        result.append(line)

        if frame == oldest_frame:
            break

        frame = frame.older()
        i    += 1
    return result

last_signal = None

def save_signal(signal):
    global last_signal
    last_signal = result = []

    if isinstance(signal, gdb.ExitedEvent):
        result.append(pwndbg.color.red('Exited: %r' % signal.exit_code))

    elif isinstance(signal, gdb.SignalEvent):
        msg = 'Program received signal %s' % signal.stop_signal
        msg = pwndbg.color.red(msg)
        msg = pwndbg.color.bold(msg)
        result.append(msg)

    elif isinstance(signal, gdb.BreakpointEvent):
        for bkpt in signal.breakpoints:
            result.append(pwndbg.color.yellow('Breakpoint %s' % (bkpt.location)))

gdb.events.cont.connect(save_signal)
gdb.events.stop.connect(save_signal)
gdb.events.exited.connect(save_signal)

def context_signal():
    return last_signal
