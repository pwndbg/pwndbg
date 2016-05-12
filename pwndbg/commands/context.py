#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import gdb
import sys

import pwndbg.arguments
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

# @pwndbg.events.stop
@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def context(*args):
    """
    Print out the current register, instruction, and stack context.

    Accepts subcommands 'reg', 'code', 'stack', 'backtrace', and 'args'.
    """
    if len(args) == 0:
        args = ['reg','code','stack','backtrace','args']

    args = [a[0] for a in args]

    result = []

    result.append(pwndbg.color.legend())
    if 'r' in args: result.extend(context_regs())
    if 'c' in args: result.extend(context_code())
    if 'c' in args: result.extend(context_source())
    if 'a' in args: result.extend(context_args())
    if 's' in args: result.extend(context_stack())
    if 'b' in args: result.extend(context_backtrace())
    result.extend(context_signal())

    for line in result:
        sys.stdout.write(line + '\n')
    sys.stdout.flush()

def context_regs():
    result = []
    result.append(pwndbg.color.blue(pwndbg.ui.banner("registers")))
    result.extend(get_regs())
    return result

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def regs(*regs):
    '''Print out all registers and enhance the information.'''
    print('\n'.join(get_regs(*regs)))

def get_regs(*regs):
    result = []

    if not regs:
        regs = pwndbg.regs.gpr + (pwndbg.regs.frame, pwndbg.regs.current.stack, pwndbg.regs.current.pc)

    changed = pwndbg.regs.changed

    for reg in regs:
        if reg is None:
            continue

        if reg not in pwndbg.regs:
            print("Unknown register: %r" % reg)
            continue

        value = pwndbg.regs[reg]

        # Make the register stand out
        regname = pwndbg.color.bold(reg.ljust(4).upper())

        # Show a dot next to the register if it changed
        m = ' ' if reg not in changed else '*'

        result.append("%s%s %s" % (m, regname, pwndbg.chain.format(value)))

    return result



def context_code():
    banner = [pwndbg.color.blue(pwndbg.ui.banner("code"))]
    result = pwndbg.commands.nearpc.nearpc(to_string=True, emulate=True)

    # If we didn't disassemble backward, try to make sure
    # that the amount of screen space taken is roughly constant.
    while len(result) < 11:
        result.append('')

    return banner + result

def context_source():
    try:
        symtab = gdb.selected_frame().find_sal().symtab
        linetable = symtab.linetable()

        closest_pc = -1
        closest_line = -1
        for line in linetable:
            if line.pc <= pwndbg.regs.pc and line.pc > closest_pc:
                closest_line = line.line
                closest_pc   = line.pc

        if closest_line < 0:
            return []

        source = gdb.execute('list %i' % closest_line, from_tty=False, to_string=True)

        # If it starts on line 1, it's not really using the
        # correct source code.
        if not source or source.startswith('1\t'):
            return []

        banner = [pwndbg.color.blue(pwndbg.ui.banner("code"))]
        banner.extend(source.splitlines())
        return banner
    except:
        pass

    if not pwndbg.ida.available():
        return []

    try:
        name = pwndbg.ida.GetFunctionName(pwndbg.regs.pc)
        addr = pwndbg.ida.LocByName(name)
        lines = pwndbg.ida.decompile(addr)
        return lines.splitlines()
    except:
        pass

    return []

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

def context_args():
    result = []

    ##################################################
    # DISABLED FOR NOW, I LIKE INLINE DISPLAY BETTER
    ##################################################
    # # For call instructions, attempt to resolve the target and
    # # determine the number of arguments.
    # for arg, value in pwndbg.arguments.arguments(pwndbg.disasm.one()):
    #     code   = False if arg.type == 'char' else True
    #     pretty = pwndbg.chain.format(value, code=code)
    #     result.append('%-10s %s' % (arg.name+':', pretty))
    # if not result:
    #         return []
    # result.insert(0, pwndbg.color.blue(pwndbg.ui.banner("arguments")))
    return result

last_signal = []

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
