#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

import gdb

import pwndbg.arguments
import pwndbg.chain
import pwndbg.color
import pwndbg.color.backtrace as B
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.commands.nearpc
import pwndbg.commands.telescope
import pwndbg.config
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

    result.append(M.legend())
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
    result.append(pwndbg.ui.banner("registers"))
    result.extend(get_regs())
    return result

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def regs(*regs):
    '''Print out all registers and enhance the information.'''
    print('\n'.join(get_regs(*regs)))

pwndbg.config.Parameter('show-flags', False, 'whether to show flags registers')
pwndbg.config.Parameter('show-retaddr-reg', False, 'whether to show return address register')

def get_regs(*regs):
    result = []

    if not regs and pwndbg.config.show_retaddr_reg:
        regs = pwndbg.regs.gpr + (pwndbg.regs.frame, pwndbg.regs.current.stack) + pwndbg.regs.retaddr + (pwndbg.regs.current.pc,)
    elif not regs:
        regs = pwndbg.regs.gpr + (pwndbg.regs.frame, pwndbg.regs.current.stack, pwndbg.regs.current.pc)

    if pwndbg.config.show_flags:
        regs += tuple(pwndbg.regs.flags)

    changed = pwndbg.regs.changed

    for reg in regs:
        if reg is None:
            continue

        if reg not in pwndbg.regs:
            print("Unknown register: %r" % reg)
            continue

        value = pwndbg.regs[reg]

        # Make the register stand out
        regname = C.register(reg.ljust(4).upper())

        # Show a dot next to the register if it changed
        change_marker = "%s" % C.config_register_changed_marker
        m = ' ' * len(change_marker) if reg not in changed else C.register_changed(change_marker)

        if reg not in pwndbg.regs.flags:
            desc = pwndbg.chain.format(value)

        else:
            names = []
            desc  = C.flag_value('%#x' % value)
            last  = pwndbg.regs.last.get(reg, 0) or 0
            flags = pwndbg.regs.flags[reg]

            for name, bit in sorted(flags.items()):
                bit = 1<<bit
                if value & bit:
                    name = name.upper()
                    name = C.flag_set(name)
                else:
                    name = name.lower()
                    name = C.flag_unset(name)

                if value & bit != last & bit:
                    name = pwndbg.color.underline(name)
                names.append(name)

            if names:
                desc = '%s %s %s %s' % (desc, C.flag_bracket('['), ' '.join(names), C.flag_bracket(']'))

        result.append("%s%s %s" % (m, regname, desc))

    return result

pwndbg.config.Parameter('emulate', True, '''
Unicorn emulation of code near the current instruction
''')

def context_code():
    banner = [pwndbg.ui.banner("code")]
    emulate = bool(pwndbg.config.emulate)
    result = pwndbg.commands.nearpc.nearpc(to_string=True, emulate=emulate)

    # If we didn't disassemble backward, try to make sure
    # that the amount of screen space taken is roughly constant.
    while len(result) < 11:
        result.append('')

    return banner + result

theme.Parameter('highlight-source', True, 'whether to highlight the closest source line')

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
        if not source or closest_line <= 1:
            return []

        # highlight the current code line
        source_lines = source.splitlines()
        if pwndbg.config.highlight_source:
            for i in range(len(source_lines)):
                if source_lines[i].startswith('%s\t' % closest_line):
                    source_lines[i] = C.highlight(source_lines[i])
                    break

        banner = [pwndbg.ui.banner("code")]
        banner.extend(source_lines)
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
    result.append(pwndbg.ui.banner("stack"))
    telescope = pwndbg.commands.telescope.telescope(pwndbg.regs.sp, to_string=True)
    if telescope:
        result.extend(telescope)
    return result

backtrace_frame_label = theme.Parameter('backtrace-frame-label', 'f ', 'frame number label for backtrace')

def context_backtrace(frame_count=10, with_banner=True):
    result = []

    if with_banner:
        result.append(pwndbg.ui.banner("backtrace"))

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
    bt_prefix = "%s" % B.config_prefix
    while True:

        prefix = bt_prefix if frame == this_frame else ' ' * len(bt_prefix)
        prefix = " %s" % B.prefix(prefix)
        addrsz = B.address(pwndbg.ui.addrsz(frame.pc()))
        symbol = B.symbol(pwndbg.symbol.get(frame.pc()))
        if symbol:
            addrsz = addrsz + ' ' + symbol
        line   = map(str, (prefix, B.frame_label('%s%i' % (backtrace_frame_label, i)), addrsz))
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
    # result.insert(0, pwndbg.ui.banner("arguments"))
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
        if signal.stop_signal == 'SIGSEGV':
            try:
                si_addr = gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr")
                msg += ' (fault address %#x)' % int(si_addr or 0)
            except gdb.error:
                pass
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
