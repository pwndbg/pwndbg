import gdb
import pwndbg.chain
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.nearpc
import pwndbg.commands.telescope
import pwndbg.disasm
import pwndbg.events
import pwndbg.ida
import pwndbg.regs
import pwndbg.symbol
import pwndbg.ui
import pwndbg.vmmap


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def context(*args):
    """
    Print out the current register, instruction, and stack context.
    """
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
    banner = [pwndbg.color.blue(pwndbg.ui.banner("code"))]
    result = pwndbg.commands.nearpc.nearpc(to_string=True)

    # If we didn't disassemble backward, try to make sure
    # that the amount of screen space taken is roughly constant.
    while len(result) < 11:
        result.insert(0, '')

    return banner + result

def context_stack():
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("stack")))
    telescope = pwndbg.commands.telescope.telescope(pwndbg.regs.sp, to_string=True)
    if telescope:
        result.extend(telescope)
    return result

def context_backtrace(frame_count=10, with_banner=True):
    result = []

    if with_banner:
        result.append(pwndbg.color.blue(pwndbg.ui.banner("backtrace")))

    this_frame    = gdb.selected_frame()
    newest_frame  = this_frame
    oldest_frame  = this_frame

    for i in range(frame_count):
        try:
            candidate = oldest_frame.older()
        except gdb.MemoryError:
            break

        if not candidate:
            break
        oldest_frame = candidate

    for i in range(frame_count):
        candidate = newest_frame.newer()
        if not candidate:
            break
        newest_frame = candidate

    frame = newest_frame
    i     = 0
    while True:
        prefix = '> ' if frame == this_frame else '  '
        addrsz = pwndbg.ui.addrsz(frame.pc())
        symbol = pwndbg.symbol.get(frame.pc())
        if symbol:
            addrsz = addrsz + ' ' + symbol
        line   = map(str, (prefix, 'f', i, addrsz))
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
        # Booooo old gdb
        if hasattr(signal, 'exit_code'):
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
