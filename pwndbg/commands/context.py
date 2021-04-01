#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import ast
import os
import sys
from collections import defaultdict
from io import open

import gdb

import pwndbg.arguments
import pwndbg.chain
import pwndbg.color
import pwndbg.color.backtrace as B
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.syntax_highlight as H
import pwndbg.commands
import pwndbg.commands.nearpc
import pwndbg.commands.telescope
import pwndbg.config
import pwndbg.disasm
import pwndbg.events
import pwndbg.ghidra
import pwndbg.ida
import pwndbg.regs
import pwndbg.symbol
import pwndbg.ui
import pwndbg.vmmap
from pwndbg.color import message
from pwndbg.color import theme


def clear_screen(out=sys.stdout):
    """
    Clear the screen by moving the cursor to top-left corner and
    clear the content
    """
    out.write('\x1b[H\x1b[J')

config_clear_screen = pwndbg.config.Parameter('context-clear-screen', False, 'whether to clear the screen before printing the context')
config_output = pwndbg.config.Parameter('context-output', 'stdout', 'where pwndbg should output ("stdout" or file/tty).')
config_context_sections = pwndbg.config.Parameter('context-sections',
                                                  'regs disasm code ghidra stack backtrace expressions',
                                                  'which context sections are displayed (controls order)')

# Storing output configuration per section
outputs = {}
output_settings = {}


@pwndbg.config.Trigger([config_context_sections])
def validate_context_sections():
    valid_values = [context.__name__.replace('context_', '') for context in context_sections.values()]

    # If someone tries to set an empty string, we let to do that informing about possible values
    # (so that it is possible to have no context at all)
    if not config_context_sections.value or config_context_sections.value.lower() in ('none', 'empty'):
        config_context_sections.value = ''
        print(message.warn("Sections set to be empty. FYI valid values are: %s" % ', '.join(valid_values)))
        return

    for section in config_context_sections.split():
        if section not in valid_values:
            print(message.warn("Invalid section: %s, valid values: %s" % (section, ', '.join(valid_values))))
            print(message.warn("(setting none of them like '' will make sections not appear)"))
            config_context_sections.revert_default()
            return

class StdOutput:
    """A context manager wrapper to give stdout"""
    def __enter__(self):
        return sys.stdout
    def __exit__(self, *args, **kwargs):
        pass
    def __hash__(self):
        return hash(sys.stdout)
    def __eq__(self, other):
        return type(other) is StdOutput

class FileOutput:
    """A context manager wrapper to reopen files on enter"""
    def __init__(self, *args):
        self.args = args
        self.handle = None
    def __enter__(self):
        self.handle = open(*self.args)
        return self.handle
    def __exit__(self, *args, **kwargs):
        self.handle.close()
    def __hash__(self):
        return hash(self.args)
    def __eq__(self, other):
        return self.args == other.args

class CallOutput:
    """A context manager which calls a function on write"""
    def __init__(self, func):
        self.func = func
    def __enter__(self):
        return self
    def __exit__(self, *args, **kwargs):
        pass
    def __hash__(self):
        return hash(self.func)
    def __eq__(self, other):
        return self.func == other.func
    def write(self, data):
        self.func(data)
    def flush(self):
        try:
            return self.func.flush()
        except AttributeError:
            pass
    def isatty(self):
        try:
            return self.func.isatty()
        except AttributeError:
            return False


def output(section):
    """Creates a context manager corresponding to configured context ouput"""
    target = outputs.get(section, str(config_output))
    if not target or target == "stdout":
        return StdOutput()
    elif callable(target):
        return CallOutput(target)
    else:
        return FileOutput(target, "w")

parser = argparse.ArgumentParser()
parser.description = "Sets the output of a context section."
parser.add_argument("section", type=str, help="The section which is to be configured. ('regs', 'disasm', 'code', 'stack', 'backtrace', and/or 'args')")
parser.add_argument("path", type=str, help="The path to which the output is written")
parser.add_argument("clearing", type=bool, help="Indicates weather to clear the output")
parser.add_argument("banner", type=str, default="both", help="Where a banner should be placed: both, top , bottom, none")
parser.add_argument("width", type=int, default=None, help="Sets a fixed width (used for banner). Set to None for auto")
@pwndbg.commands.ArgparsedCommand(parser, aliases=['ctx-out'])
def contextoutput(section, path, clearing, banner="both", width=None):
    outputs[section] = path
    output_settings[section] = dict(clearing=clearing,
                                    width=width,
                                    banner_top= banner in ["both", "top"],
                                    banner_bottom= banner in ["both", "bottom"])

# Watches
expressions = set()
expression_commands = {
    "eval": gdb.parse_and_eval,
    "execute": lambda exp: gdb.execute(exp, False, True)
}

parser = argparse.ArgumentParser()
parser.description = """
Adds an expression to be shown on context.

'cmd' controls what command is used to interpret the expression.
eval: the expression is parsed and evaluated as in the debugged language
execute: the expression is executed as an gdb command
"""
parser.add_argument("cmd", type=str, default="eval", nargs="?",
                    help="Command to be used with the expression. Values are: eval execute")
parser.add_argument("expression", type=str, help="The expression to be evaluated and shown in context")
@pwndbg.commands.ArgparsedCommand(parser, aliases=['ctx-watch', 'cwatch'])
def contextwatch(expression, cmd=None):
    expressions.add((expression, expression_commands.get(cmd, gdb.parse_and_eval)))

parser = argparse.ArgumentParser()
parser.description = """Removes an expression previously added to be watched."""
parser.add_argument("expression", type=str, help="The expression to be removed from context")
@pwndbg.commands.ArgparsedCommand(parser, aliases=['ctx-unwatch', 'cunwatch'])
def contextunwatch(expression):
    global expressions
    expressions = set((exp,cmd) for exp,cmd in expressions if exp != expression)

def context_expressions(target=sys.stdout, with_banner=True, width=None):
    if not expressions:
        return []
    banner = [pwndbg.ui.banner("expressions", target=target, width=width)]
    output = []
    if width is None:
        _height, width = pwndbg.ui.get_window_size(target=target)
    for exp,cmd in sorted(expressions):
        try:
            # value = gdb.parse_and_eval(exp)
            value = str(cmd(exp))
        except gdb.error as err:
            value = str(err)
        value = value.split("\n")
        lines = []
        for line in value:
            if width and len(line)+len(exp)+3 > width:
                n = width - (len(exp)+3) - 1 # 1 Padding...
                lines.extend(line[i:i+n] for i in range(0, len(line), n))
            else:
                lines.append(line)

        fmt = C.highlight(exp)
        lines[0] = "{} = {}".format(fmt, lines[0])
        lines[1:] = [" "*(len(exp)+3) + line for line in lines[1:]]
        output.extend(lines)
    return banner + output if with_banner else output


config_context_ghidra = pwndbg.config.Parameter('context-ghidra',
                                                'never',
                                                'when to try to decompile the current function with ghidra (slow and requires radare2/r2pipe) (valid values: always, never, if-no-source)')


def context_ghidra(target=sys.stdout, with_banner=True, width=None):
    """
    Print out the source of the current function decompiled by ghidra.

    The context-ghidra config parameter is used to configure whether to always,
    never or only show the context if no source is available.
    """
    banner = [pwndbg.ui.banner("ghidra decompile", target=target, width=width)] if with_banner else []

    if config_context_ghidra == "never":
        return []

    if config_context_ghidra == "if-no-source":
        source_filename = pwndbg.symbol.selected_frame_source_absolute_filename()
        if source_filename and os.path.exists(source_filename):
            return []

    try:
        return banner + pwndbg.ghidra.decompile().split('\n')
    except Exception as e:
        return banner + [message.error(e)]



# @pwndbg.events.stop

parser = argparse.ArgumentParser()
parser.description = "Print out the current register, instruction, and stack context."
parser.add_argument("subcontext", nargs="*", type=str, default=None, help="Submenu to display: 'reg', 'disasm', 'code', 'stack', 'backtrace', 'ghidra', and/or 'args'")
@pwndbg.commands.ArgparsedCommand(parser, aliases=['ctx'])
@pwndbg.commands.OnlyWhenRunning
def context(subcontext=None):
    """
    Print out the current register, instruction, and stack context.

    Accepts subcommands 'reg', 'disasm', 'code', 'stack', 'backtrace', 'ghidra' and 'args'.
    """
    if subcontext is None:
        subcontext = []
    args = subcontext

    if len(args) == 0:
        args = config_context_sections.split()

    sections = [("legend", lambda target=None, **kwargs: [M.legend()])] if args else []
    sections += [(arg, context_sections.get(arg[0], None)) for arg in args]

    result = defaultdict(list)
    result_settings = defaultdict(dict)
    for section, func in sections:
        if func:
            target = output(section)
            # Last section of an output decides about output settings
            settings = output_settings.get(section, {})
            result_settings[target].update(settings)
            with target as out:
                result[target].extend(func(target=out,
                                           width=settings.get("width", None),
                                           with_banner=settings.get("banner_top", True)))

    for target, res in result.items():
        settings = result_settings[target]
        if len(res) > 0 and settings.get("banner_bottom", True):
            with target as out:
                res.append(pwndbg.ui.banner("", target=out,
                                            width=settings.get("width", None)))

    for target, lines in result.items():
        with target as out:
            if result_settings[target].get("clearing", config_clear_screen) and lines:
                clear_screen(out)
            out.write("\n".join(lines))
            if out is sys.stdout:
                out.write('\n')
            out.flush()


pwndbg.config.Parameter('show-compact-regs', False, 'whether to show a compact register view')
pwndbg.config.Parameter('show-compact-regs-align', 20, 'the number of characters reserved for each register and value')
pwndbg.config.Parameter('show-compact-regs-space', 4, 'the minimum number of characters separating each register')


def calculate_padding_to_align(length, align):
    ''' Calculates the number of spaces to append to reach the next alignment.
        The next alignment point is given by "x * align >= length".
    '''
    return 0 if length % align == 0 else (align - (length % align))


def compact_regs(regs, width):
    align = int(pwndbg.config.show_compact_regs_align)
    space = int(pwndbg.config.show_compact_regs_space)
    result = []

    line = ''
    line_length = 0
    for reg in regs:
        reg_length = len(pwndbg.color.strip(reg))

        # Length of line with space and padding is required for fitting the
        # register string onto the screen / display
        line_length_with_padding = line_length
        line_length_with_padding += space if line_length != 0 else 0
        line_length_with_padding += calculate_padding_to_align(line_length_with_padding, align)

        # When element does not fully fit, then start a new line
        if line_length_with_padding + max(reg_length, align) > width:
            result.append(line)

            line = ''
            line_length = 0
            line_length_with_padding = 0

        # Add padding
        if line != '':
            line += ' ' * (line_length_with_padding - line_length)

        line += reg
        line_length = line_length_with_padding + reg_length

    if line != '':
        result.append(line)

    return result


def context_regs(target=sys.stdout, with_banner=True, width=None):
    if width is None:
        _height, width = pwndbg.ui.get_window_size(target=target)

    regs = get_regs()
    if pwndbg.config.show_compact_regs:
        regs = compact_regs(regs, width)

    banner = [pwndbg.ui.banner("registers", target=target, width=width)]
    return banner + regs if with_banner else regs


parser = argparse.ArgumentParser()
parser.description = '''Print out all registers and enhance the information.'''
parser.add_argument("regs", nargs="*", type=str, default=None, help="Registers to be shown")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def regs(regs=None):
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
            message.warn("Unknown register: %r" % reg)
            continue

        value = pwndbg.regs[reg]

        # Make the register stand out
        regname = C.register(reg.ljust(4).upper())

        # Show a dot next to the register if it changed
        change_marker = "%s" % C.config_register_changed_marker
        m = ' ' * len(change_marker) if reg not in changed else C.register_changed(change_marker)

        if reg in pwndbg.regs.flags:
            desc = C.format_flags(value, pwndbg.regs.flags[reg], pwndbg.regs.last.get(reg, 0))

        else:
            desc = pwndbg.chain.format(value)

        result.append("%s%s %s" % (m, regname, desc))

    return result

pwndbg.config.Parameter('emulate', True, '''
Unicorn emulation of code near the current instruction
''')
code_lines = pwndbg.config.Parameter('context-code-lines', 10, 'number of additional lines to print in the code context')

def context_disasm(target=sys.stdout, with_banner=True, width=None):
    try:
        flavor = gdb.execute('show disassembly-flavor', to_string=True).lower().split('"')[1]
    except gdb.error as e:
        if str(e).find("disassembly-flavor") > -1:
            flavor = 'intel'
        else:
            raise

    syntax = pwndbg.disasm.CapstoneSyntax[flavor]

    # Get the Capstone object to set disassembly syntax
    cs = next(iter(pwndbg.disasm.get_disassembler_cached.cache.values()), None)

    # The `None` case happens when the cache was not filled yet (see e.g. #881)
    if cs is not None and cs.syntax != syntax:
        pwndbg.memoize.reset()

    banner = [pwndbg.ui.banner("disasm", target=target, width=width)]
    emulate = bool(pwndbg.config.emulate)
    result = pwndbg.commands.nearpc.nearpc(to_string=True, emulate=emulate, lines=code_lines // 2)

    # If we didn't disassemble backward, try to make sure
    # that the amount of screen space taken is roughly constant.
    while len(result) < code_lines + 1:
        result.append('')

    return banner + result if with_banner else result

theme.Parameter('highlight-source', True, 'whether to highlight the closest source line')
source_code_lines = pwndbg.config.Parameter('context-source-code-lines',
                                             10,
                                             'number of source code lines to print by the context command')
theme.Parameter('code-prefix', '►', "prefix marker for 'context code' command")

@pwndbg.memoize.reset_on_start
def get_highlight_source(filename):
    # Notice that the code is cached
    with open(filename, encoding='utf-8') as f:
        source = f.read()

    if pwndbg.config.syntax_highlight:
        source = H.syntax_highlight(source, filename)

    source_lines = source.splitlines()
    source_lines = tuple(line.rstrip() for line in source_lines)
    return source_lines

def get_filename_and_formatted_source():
    """
    Returns formatted, lines limited and highlighted source as list
    or if it isn't there - an empty list
    """
    sal = gdb.selected_frame().find_sal()  # gdb.Symtab_and_line

    # Check if source code is available
    if sal.symtab is None:
        return '', []

    # Get the full source code
    closest_line = sal.line
    filename = sal.symtab.fullname()

    try:
        source = get_highlight_source(filename)
    except IOError:
        return '', []

    if not source:
        return '', []

    n = int(source_code_lines)

    # Compute the line range
    start = max(closest_line - 1 - n//2, 0)
    end = min(closest_line - 1 + n//2 + 1, len(source))
    num_width = len(str(end))

    # split the code
    source = source[start:end]

    # Compute the prefix_sign length
    prefix_sign = pwndbg.config.code_prefix
    prefix_width = len(prefix_sign)

    # Format the output
    formatted_source = []
    for line_number, code in enumerate(source, start=start + 1):
        fmt = ' {prefix_sign:{prefix_width}} {line_number:>{num_width}} {code}'
        if pwndbg.config.highlight_source and line_number == closest_line:
            fmt = C.highlight(fmt)

        line = fmt.format(
            prefix_sign=C.prefix(prefix_sign) if line_number == closest_line else '',
            prefix_width=prefix_width,
            line_number=line_number,
            num_width=num_width,
            code=code
        )
        formatted_source.append(line)

    return filename, formatted_source


def context_code(target=sys.stdout, with_banner=True, width=None):
    filename, formatted_source = get_filename_and_formatted_source()

    # Try getting source from files
    if formatted_source:
        bannerline = [pwndbg.ui.banner("Source (code)", target=target, width=width)] if with_banner else []
        return bannerline + ['In file: %s' % filename] + formatted_source

    # Try getting source from IDA Pro Hex-Rays Decompiler
    if not pwndbg.ida.available():
        return []

    n = int(int(int(source_code_lines) / 2)) # int twice to make it a real int instead of inthook
    # May be None when decompilation failed or user loaded wrong binary in IDA
    code = pwndbg.ida.decompile_context(pwndbg.regs.pc, n)

    if code:
        bannerline = [pwndbg.ui.banner("Hexrays pseudocode", target=target, width=width)] if with_banner else []
        return bannerline + code.splitlines()
    else:
        return []


stack_lines = pwndbg.config.Parameter('context-stack-lines', 8, 'number of lines to print in the stack context')

def context_stack(target=sys.stdout, with_banner=True, width=None):
    result = [pwndbg.ui.banner("stack", target=target, width=width)] if with_banner else []
    telescope = pwndbg.commands.telescope.telescope(pwndbg.regs.sp, to_string=True, count=stack_lines)
    if telescope:
        result.extend(telescope)
    return result


backtrace_lines = pwndbg.config.Parameter('context-backtrace-lines', 8, 'number of lines to print in the backtrace context')
backtrace_frame_label = theme.Parameter('backtrace-frame-label', 'f ', 'frame number label for backtrace')

def context_backtrace(with_banner=True, target=sys.stdout, width=None):
    result = []

    if with_banner:
        result.append(pwndbg.ui.banner("backtrace", target=target, width=width))

    this_frame    = gdb.selected_frame()
    newest_frame  = this_frame
    oldest_frame  = this_frame

    for i in range(backtrace_lines-1):
        try:
            candidate = oldest_frame.older()
        except gdb.MemoryError:
            break

        if not candidate:
            break
        oldest_frame = candidate

    for i in range(backtrace_lines-1):
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


def context_args(with_banner=True, target=sys.stdout, width=None):
    args = pwndbg.arguments.format_args(pwndbg.disasm.one())

    # early exit to skip section if no arg found
    if not args:
        return []

    if with_banner:
        args.insert(0, pwndbg.ui.banner("arguments", target=target, width=width))

    return args

last_signal = []


def save_signal(signal):
    global last_signal
    last_signal = result = []

    if isinstance(signal, gdb.ExitedEvent):
        # Booooo old gdb
        if hasattr(signal, 'exit_code'):
            result.append(message.exit('Exited: %r' % signal.exit_code))

    elif isinstance(signal, gdb.SignalEvent):
        msg = 'Program received signal %s' % signal.stop_signal

        if signal.stop_signal == 'SIGSEGV':

            # When users use rr (https://rr-project.org or https://github.com/mozilla/rr)
            # we can't access $_siginfo, so lets just show current pc
            # see also issue 476
            if _is_rr_present():
                msg += ' (current pc: %#x)' % pwndbg.regs.pc
            else:
                try:
                    si_addr = gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr")
                    msg += ' (fault address %#x)' % int(si_addr or 0)
                except gdb.error:
                    pass
        result.append(message.signal(msg))

    elif isinstance(signal, gdb.BreakpointEvent):
        for bkpt in signal.breakpoints:
            result.append(message.breakpoint('Breakpoint %s' % (bkpt.location)))

gdb.events.cont.connect(save_signal)
gdb.events.stop.connect(save_signal)
gdb.events.exited.connect(save_signal)


def context_signal():
    return last_signal


context_sections = {
    'r': context_regs,
    'd': context_disasm,
    'a': context_args,
    'c': context_code,
    's': context_stack,
    'b': context_backtrace,
    'e': context_expressions,
    'g': context_ghidra,
}


@pwndbg.memoize.forever
def _is_rr_present():
    """
    Checks whether rr project is present (so someone launched e.g. `rr replay <some-recording>`)
    """

    # this is ugly but I couldn't find a better way to do it
    # feel free to refactor it
    globals_list_literal_str = gdb.execute('python print(list(globals().keys()))', to_string=True)
    interpreter_globals = ast.literal_eval(globals_list_literal_str)

    return 'RRCmd' in interpreter_globals and 'RRWhere' in interpreter_globals
