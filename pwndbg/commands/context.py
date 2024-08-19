from __future__ import annotations

import argparse
import ast
import os
import sys
from collections import defaultdict
from typing import Any
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Tuple

import gdb

import pwndbg
import pwndbg.aglib.disasm
import pwndbg.arguments
import pwndbg.chain
import pwndbg.color
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.syntax_highlight as H
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.gdblib.heap_tracking
import pwndbg.gdblib.nearpc
import pwndbg.gdblib.regs
import pwndbg.gdblib.symbol
import pwndbg.gdblib.vmmap
import pwndbg.ghidra
import pwndbg.integration
import pwndbg.ui
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import message
from pwndbg.color import theme
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.arch import get_thumb_mode_string

theme.add_param("backtrace-prefix", "►", "prefix for current backtrace label")

# TODO: Should namespace be "context.backtrace"?
c = ColorConfig(
    "backtrace",
    [
        ColorParamSpec("prefix", "none", "color for prefix of current backtrace label"),
        ColorParamSpec("address", "none", "color for backtrace (address)"),
        ColorParamSpec("symbol", "none", "color for backtrace (symbol)"),
        ColorParamSpec("frame-label", "none", "color for backtrace (frame label)"),
    ],
)


def clear_screen(out=sys.stdout) -> None:
    """
    Clear the screen by moving the cursor to top-left corner and
    clearing the content. Different terminals may act differently
    """
    ## The ANSI escape codes we use here are described e.g. on:
    # https://en.wikipedia.org/wiki/ANSI_escape_code#CSIsection
    #
    ## To sum up the escape codes used below:
    # \x1b - Escape | Starts all the escape sequences
    # [ - Control Sequence Introducer | Starts most of the useful sequences
    # H - Cursor Position | Moves the cursor to row n, column m (default=1)
    # \x1b - Escape | Starts all the escape sequences
    # <n> J - Erase in Display | Clears part of the screen.
    # If n is 0 (or missing), clear from cursor to end of screen.
    # If n is 1, clear from cursor to beginning of the screen.
    # If n is 2, clear entire screen (and moves cursor to upper left on DOS ANSI.SYS).
    # If n is 3, clear entire screen and delete all lines saved in the
    # scrollback buffer (this feature was added for xterm and is supported
    # by other terminal applications
    out.write("\x1b[H\x1b[2J")


config_clear_screen = pwndbg.config.add_param(
    "context-clear-screen", False, "whether to clear the screen before printing the context"
)
config_output = pwndbg.config.add_param(
    "context-output", "stdout", 'where pwndbg should output ("stdout" or file/tty).'
)
config_context_sections = pwndbg.config.add_param(
    "context-sections",
    "regs disasm code ghidra stack backtrace expressions threads heap-tracker",
    "which context sections are displayed (controls order)",
)
config_max_threads_display = pwndbg.config.add_param(
    "context-max-threads",
    4,
    "maximum number of threads displayed by the context command",
)

# Storing output configuration per section
outputs: Dict[str, str] = {}
output_settings = {}


@pwndbg.config.trigger(config_context_sections)
def validate_context_sections() -> None:
    valid_values = [
        context.__name__.replace("context_", "") for context in context_sections.values()
    ]

    # If someone tries to set an empty string, we let to do that informing about possible values
    # (so that it is possible to have no context at all)
    if not config_context_sections.value or config_context_sections.value.lower() in (
        "''",
        '""',
        "none",
        "empty",
        "-",
    ):
        config_context_sections.value = ""
        print(
            message.warn(
                f"Sections set to be empty. FYI valid values are: {', '.join(valid_values)}"
            )
        )
        return

    for section in config_context_sections.split():
        if section not in valid_values:
            print(
                message.warn(f"Invalid section: {section}, valid values: {', '.join(valid_values)}")
            )
            print(message.warn("(setting none of them like '' will make sections not appear)"))
            config_context_sections.revert_default()
            return


class StdOutput:
    """A context manager wrapper to give stdout"""

    def __enter__(self):
        return sys.stdout

    def __exit__(self, *args, **kwargs) -> None:
        pass

    def __hash__(self):
        return hash(sys.stdout)

    def __eq__(self, other) -> bool:
        return isinstance(other, StdOutput)


class FileOutput:
    """A context manager wrapper to reopen files on enter"""

    def __init__(self, *args) -> None:
        self.args = args
        self.handle = None

    def __enter__(self):
        self.handle = open(*self.args)
        return self.handle

    def __exit__(self, *args, **kwargs) -> None:
        self.handle.close()

    def __hash__(self):
        return hash(self.args)

    def __eq__(self, other):
        return self.args == other.args


class CallOutput:
    """A context manager which calls a function on write"""

    def __init__(self, func) -> None:
        self.func = func

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs) -> None:
        pass

    def __hash__(self):
        return hash(self.func)

    def __eq__(self, other):
        return self.func == other.func

    def write(self, data) -> None:
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


def output(section: str):
    """Creates a context manager corresponding to configured context output"""
    target = outputs.get(section, str(config_output))
    if not target or target == "stdout":
        return StdOutput()
    elif callable(target):
        return CallOutput(target)
    else:
        return FileOutput(target, "w")


parser = argparse.ArgumentParser(description="Sets the output of a context section.")
parser.add_argument(
    "section",
    type=str,
    help="The section which is to be configured. ('regs', 'disasm', 'code', 'stack', 'backtrace', and/or 'args')",
)
parser.add_argument("path", type=str, help="The path to which the output is written")
parser.add_argument("clearing", type=bool, help="Indicates weather to clear the output")
banner_arg = parser.add_argument(
    "banner",
    type=str,
    nargs="?",
    default="both",
    help="Where a banner should be placed: both, top , bottom, none",
)
parser.add_argument(
    "width",
    type=int,
    nargs="?",
    default=None,
    help="Sets a fixed width (used for banner). Set to None for auto",
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["ctx-out"], category=CommandCategory.CONTEXT)
def contextoutput(section, path, clearing, banner="both", width: int = None):
    if not banner:  # synonym for splitmind backwards compatibility
        banner = "none"
    if banner not in ("both", "top", "bottom", "none"):
        raise argparse.ArgumentError(banner_arg, f"banner can not be '{banner}'")

    outputs[section] = path
    output_settings[section] = {
        "clearing": clearing,
        "width": width,
        "banner_top": banner in ["both", "top"],
        "banner_bottom": banner in ["both", "bottom"],
    }


# Watches
expressions = []

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
Adds an expression to be shown on context.

To remove an expression, see `cunwatch`.
""",
)
parser.add_argument(
    "cmd",
    type=str,
    default="eval",
    nargs="?",
    choices=["eval", "execute"],
    help="""Command to be used with the expression.
- eval: the expression is parsed and evaluated as in the debugged language.
- execute: the expression is executed as a GDB command.""",
)
parser.add_argument(
    "expression", type=str, help="The expression to be evaluated and shown in context"
)


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["ctx-watch", "cwatch"], category=CommandCategory.CONTEXT
)
def contextwatch(expression, cmd) -> None:
    expressions.append((expression, cmd))


parser = argparse.ArgumentParser(
    description="Removes an expression previously added to be watched."
)
parser.add_argument("num", type=int, help="The expression number to be removed from context")


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["ctx-unwatch", "cunwatch"], category=CommandCategory.CONTEXT
)
def contextunwatch(num) -> None:
    if num < 1 or num > len(expressions):
        print(message.error("Invalid input"))
        return

    expressions.pop(int(num) - 1)


def context_expressions(target=sys.stdout, with_banner=True, width=None):
    if not expressions:
        return []
    banner = [pwndbg.ui.banner("expressions", target=target, width=width)]
    output = []
    for i, (exp, cmd) in enumerate(expressions):
        header = f"{i + 1}: {C.highlight(exp)}"
        try:
            if cmd == "eval":
                value = str(gdb.parse_and_eval(exp))
            else:
                assert cmd == "execute"
                value = gdb.execute(exp, from_tty=False, to_string=True)
        except gdb.error as err:
            value = str(err)

        # When evaluating the expression we display it inline with the header, but when executing an
        # expression we display it on the next line
        if cmd == "eval":
            header += f" = {value}"
        output.append(header)

        if cmd == "execute":
            output.append(value)

    return banner + output if with_banner else output


config_context_ghidra = pwndbg.config.add_param(
    "context-ghidra",
    "never",
    "when to try to decompile the current function with ghidra (slow and requires radare2/r2pipe or rizin/rzpipe) (valid values: always, never, if-no-source)",
)


def context_ghidra(target=sys.stdout, with_banner=True, width=None):
    """
    Print out the source of the current function decompiled by ghidra.

    The context-ghidra config parameter is used to configure whether to always,
    never or only show the context if no source is available.
    """
    banner = (
        [pwndbg.ui.banner("ghidra decompile", target=target, width=width)] if with_banner else []
    )

    if config_context_ghidra == "never":
        return []

    if config_context_ghidra == "if-no-source":
        source_filename = pwndbg.gdblib.symbol.selected_frame_source_absolute_filename()
        if source_filename and os.path.exists(source_filename):
            return []

    try:
        return banner + pwndbg.ghidra.decompile().split("\n")
    except Exception as e:
        return banner + [message.error(e)]


parser = argparse.ArgumentParser(
    description="Print out the current register, instruction, and stack context."
)
parser.add_argument(
    "subcontext",
    nargs="*",
    type=str,
    default=None,
    help="Submenu to display: 'reg', 'disasm', 'code', 'stack', 'backtrace', 'ghidra', and/or 'args'",
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["ctx"], category=CommandCategory.CONTEXT)
@pwndbg.commands.OnlyWhenRunning
def context(subcontext=None) -> None:
    """
    Print out the current register, instruction, and stack context.

    Accepts subcommands 'reg', 'disasm', 'code', 'stack', 'backtrace', 'ghidra' and 'args'.
    """
    if subcontext is None:
        subcontext = []
    args = subcontext

    if len(args) == 0:
        args = config_context_sections.split()

    sections = [("legend", lambda *args, **kwargs: [M.legend()])] if args else []
    sections += [(arg, context_sections.get(arg[0], None)) for arg in args]

    result = defaultdict(list)
    result_settings: DefaultDict[str, Dict[Any, Any]] = defaultdict(dict)
    for section, func in sections:
        if func:
            target = output(section)
            # Last section of an output decides about output settings
            settings = output_settings.get(section, {})
            result_settings[target].update(settings)
            with target as out:
                result[target].extend(
                    func(
                        target=out,
                        width=settings.get("width", None),
                        with_banner=settings.get("banner_top", True),
                    )
                )

    for target, res in result.items():
        settings = result_settings[target]
        if len(res) > 0 and settings.get("banner_bottom", True):
            with target as out:
                res.append(pwndbg.ui.banner("", target=out, width=settings.get("width", None)))

    for target, lines in result.items():
        with target as out:
            if result_settings[target].get("clearing", config_clear_screen) and lines:
                clear_screen(out)
            out.write("\n".join(lines))
            if out is sys.stdout:
                out.write("\n")
            out.flush()


pwndbg.config.add_param(
    "show-compact-regs", False, "whether to show a compact register view with columns"
)
pwndbg.config.add_param(
    "show-compact-regs-columns", 2, "the number of columns (0 for dynamic number of columns)"
)
pwndbg.config.add_param("show-compact-regs-min-width", 20, "the minimum width of each column")
pwndbg.config.add_param(
    "show-compact-regs-separation", 4, "the number of spaces separating columns"
)


def calculate_padding_to_align(length, align):
    """Calculates the number of spaces to append to reach the next alignment.
    The next alignment point is given by "x * align >= length".
    """
    return 0 if length % align == 0 else (align - (length % align))


def compact_regs(regs, width=None, target=sys.stdout):
    columns = max(0, int(pwndbg.config.show_compact_regs_columns))
    min_width = max(1, int(pwndbg.config.show_compact_regs_min_width))
    separation = max(1, int(pwndbg.config.show_compact_regs_separation))

    if width is None:  # auto width. In case of stdout, it's better to use stdin (b/c GdbOutputFile)
        _height, width = pwndbg.ui.get_window_size(
            target=target if target != sys.stdout else sys.stdin
        )

    if columns > 0:
        # Adjust the minimum_width (column) according to the
        # layout depicted below, where there are "columns" columns
        # and "columns - 1" separations.
        #
        # |<----------------- window width -------------------->|
        # | column | sep. | column | sep. | ... | sep. | column |
        #
        # Which results in the following formula:
        # window_width = columns * min_width + (columns - 1) * separation
        # => min_width = (window_width - (columns - 1) * separation) / columns
        min_width = max(min_width, (width - (columns - 1) * separation) // columns)

    result = []

    line = ""
    line_length = 0
    for reg in regs:
        # Strip the color / hightlight information the get the raw text width of the register
        reg_length = len(pwndbg.color.strip(reg))

        # Length of line with unoccupied space and padding is required
        # to fit the register string onto the screen / display.
        line_length_with_padding = line_length
        line_length_with_padding += (
            separation if line_length != 0 else 0
        )  # No separation at the start of a line
        line_length_with_padding += calculate_padding_to_align(
            line_length_with_padding, min_width + separation
        )

        # When element does not fully fit, then start a new line
        if line_length_with_padding + max(reg_length, min_width) > width:
            result.append(line)

            line = ""
            line_length = 0
            line_length_with_padding = 0

        # Add padding in front of the next printed register
        if line_length != 0:
            line += " " * (line_length_with_padding - line_length)

        line += reg
        line_length = line_length_with_padding + reg_length

    # Append last line if required
    if line_length != 0:
        result.append(line)

    return result


def context_regs(target=sys.stdout, with_banner=True, width=None):
    regs = get_regs()
    if pwndbg.config.show_compact_regs:
        regs = compact_regs(regs, target=target, width=width)

    info = " / show-flags {} / show-compact-regs {}".format(
        "on" if pwndbg.config.show_flags else "off",
        "on" if pwndbg.config.show_compact_regs else "off",
    )
    banner = [pwndbg.ui.banner("registers", target=target, width=width, extra=info)]
    return banner + regs if with_banner else regs


def context_heap_tracker(target=sys.stdout, with_banner=True, width=None):
    if not pwndbg.gdblib.heap_tracking.is_enabled():
        return []

    banner = [pwndbg.ui.banner("heap tracker", target=target, width=width, extra="")]

    if pwndbg.gdblib.heap_tracking.last_issue is not None:
        info = [f"Detected the following potential issue: {pwndbg.gdblib.heap_tracking.last_issue}"]
        pwndbg.gdblib.heap_tracking.last_issue = None
    else:
        info = ["Nothing to report."]

    return banner + info if with_banner else info


parser = argparse.ArgumentParser(description="Print out all registers and enhance the information.")
parser.add_argument("regs", nargs="*", type=str, default=None, help="Registers to be shown")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.CONTEXT)
@pwndbg.commands.OnlyWhenRunning
def regs(regs=[]) -> None:
    """Print out all registers and enhance the information."""
    print("\n".join(get_regs(regs)))


pwndbg.config.add_param("show-flags", False, "whether to show flags registers")
pwndbg.config.add_param("show-retaddr-reg", True, "whether to show return address register")


def get_regs(regs: List[str] = None):
    result = []

    if regs is None:
        regs = []

    if len(regs) == 0:
        regs += pwndbg.gdblib.regs.gpr

        regs.append(pwndbg.gdblib.regs.frame)
        regs.append(pwndbg.gdblib.regs.stack)

        if pwndbg.config.show_retaddr_reg:
            regs += pwndbg.gdblib.regs.retaddr

        regs.append(pwndbg.gdblib.regs.current.pc)

        if pwndbg.config.show_flags:
            regs += pwndbg.gdblib.regs.flags.keys()

    changed = pwndbg.gdblib.regs.changed

    for reg in regs:
        if reg is None:
            continue

        value = pwndbg.gdblib.regs[reg]
        if value is None:
            print(message.warn("Unknown register: %r" % reg))
            continue

        # Make the register stand out and give a color if changed
        regname = C.register(reg.ljust(4).upper())
        if reg in changed:
            regname = C.register_changed(regname)

        # Show a dot next to the register if it changed
        change_marker = "%s" % C.config_register_changed_marker
        m = " " * len(change_marker) if reg not in changed else C.register_changed(change_marker)

        bit_flags = None
        if reg in pwndbg.gdblib.regs.flags:
            bit_flags = pwndbg.gdblib.regs.flags[reg]
        elif reg in pwndbg.gdblib.regs.extra_flags:
            bit_flags = pwndbg.gdblib.regs.extra_flags[reg]

        if bit_flags:
            desc = C.format_flags(value, bit_flags, pwndbg.gdblib.regs.last.get(reg, 0))

        else:
            desc = pwndbg.chain.format(value)

        result.append(f"{m}{regname} {desc}")
    return result


disasm_lines = pwndbg.config.add_param(
    "context-disasm-lines", 10, "number of additional lines to print in the disasm context"
)


def context_disasm(target=sys.stdout, with_banner=True, width=None):
    try:
        flavor = gdb.execute("show disassembly-flavor", to_string=True).lower().split('"')[1]
    except gdb.error as e:
        if str(e).find("disassembly-flavor") > -1:
            flavor = "intel"
        else:
            raise

    syntax = pwndbg.aglib.disasm.CapstoneSyntax[flavor]

    # Get the Capstone object to set disassembly syntax
    cs = next(iter(pwndbg.aglib.disasm.get_disassembler_cached.cache.values()), None)

    # The `None` case happens when the cache was not filled yet (see e.g. #881)
    if cs is not None and cs.syntax != syntax:
        pwndbg.lib.cache.clear_caches()

    result = pwndbg.gdblib.nearpc.nearpc(
        lines=disasm_lines // 2,
        emulate=bool(not pwndbg.config.emulate == "off"),
        use_cache=True,
    )

    # Note: we must fetch emulate value again after disasm since
    # we check if we can actually use emulation in `can_run_first_emulate`
    # and this call may disable it
    thumb_mode_str = get_thumb_mode_string()
    if thumb_mode_str is not None:
        info = " / {} / {} mode / set emulate {}".format(
            pwndbg.gdblib.arch.current, thumb_mode_str, pwndbg.config.emulate
        )
    else:
        info = " / {} / set emulate {}".format(pwndbg.gdblib.arch.current, pwndbg.config.emulate)
    banner = [pwndbg.ui.banner("disasm", target=target, width=width, extra=info)]

    # If we didn't disassemble backward, try to make sure
    # that the amount of screen space taken is roughly constant.
    while len(result) < disasm_lines + 1:
        result.append("")

    return banner + result if with_banner else result


theme.add_param("highlight-source", True, "whether to highlight the closest source line")
source_disasm_lines = pwndbg.config.add_param(
    "context-code-lines", 10, "number of source code lines to print by the context command"
)
pwndbg.config.add_param(
    "context-code-tabstop", 8, "number of spaces that a <tab> in the source code counts for"
)
theme.add_param("code-prefix", "►", "prefix marker for 'context code' command")


@pwndbg.lib.cache.cache_until("start")
def get_highlight_source(filename: str) -> Tuple[str, ...]:
    # Notice that the code is cached
    with open(filename, encoding="utf-8", errors="ignore") as f:
        source = f.read()

    if pwndbg.config.syntax_highlight:
        source = H.syntax_highlight(source, filename)

    source_lines = source.split("\n")
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
        return "", []

    # Get the full source code
    closest_line = sal.line
    filename = sal.symtab.fullname()

    try:
        source = get_highlight_source(filename)
    except OSError:
        return "", []

    if not source:
        return "", []

    n = int(source_disasm_lines)

    # Compute the line range
    start = max(closest_line - 1 - n // 2, 0)
    end = min(closest_line - 1 + n // 2 + 1, len(source))
    num_width = len(str(end))

    # split the code
    source = source[start:end]

    # Compute the prefix_sign length
    prefix_sign = C.prefix(str(pwndbg.config.code_prefix))
    prefix_width = len(prefix_sign)

    # Format the output
    formatted_source = []
    for line_number, code in enumerate(source, start=start + 1):
        if pwndbg.config.context_code_tabstop > 0:
            code = code.replace("\t", " " * pwndbg.config.context_code_tabstop)
        fmt = " {prefix_sign:{prefix_width}} {line_number:>{num_width}} {code}"
        if pwndbg.config.highlight_source and line_number == closest_line:
            fmt = C.highlight(fmt)

        line = fmt.format(
            prefix_sign=prefix_sign if line_number == closest_line else "",
            prefix_width=prefix_width,
            line_number=line_number,
            num_width=num_width,
            code=code,
        )
        formatted_source.append(line)

    return filename, formatted_source


should_decompile = pwndbg.config.add_param(
    "context-integration-decompile",
    True,
    "whether context should fall back to decompilation with no source code",
)


def context_code(target=sys.stdout, with_banner=True, width=None):
    filename, formatted_source = get_filename_and_formatted_source()

    # Try getting source from files
    if formatted_source:
        bannerline = (
            [pwndbg.ui.banner("Source (code)", target=target, width=width)] if with_banner else []
        )
        return (
            bannerline
            + ["In file: %s:%d" % (filename, gdb.selected_frame().find_sal().line)]
            + formatted_source
        )

    if should_decompile:
        # Will be None if decompilation fails
        code = pwndbg.integration.provider.decompile(
            pwndbg.gdblib.regs.pc, int(source_disasm_lines)
        )

        if code:
            bannerline = (
                [pwndbg.ui.banner("Decomp", target=target, width=width)] if with_banner else []
            )
            return bannerline + code
        else:
            return []


stack_lines = pwndbg.config.add_param(
    "context-stack-lines", 8, "number of lines to print in the stack context"
)


def context_stack(target=sys.stdout, with_banner=True, width=None):
    result = [pwndbg.ui.banner("stack", target=target, width=width)] if with_banner else []
    telescope = pwndbg.commands.telescope.telescope(
        pwndbg.gdblib.regs.sp, to_string=True, count=stack_lines
    )
    if telescope:
        result.extend(telescope)
    return result


backtrace_lines = pwndbg.config.add_param(
    "context-backtrace-lines", 8, "number of lines to print in the backtrace context"
)
backtrace_frame_label = theme.add_param(
    "backtrace-frame-label", "", "frame number label for backtrace"
)


def context_backtrace(with_banner=True, target=sys.stdout, width=None):
    result = []

    if with_banner:
        result.append(pwndbg.ui.banner("backtrace", target=target, width=width))

    this_frame = gdb.selected_frame()
    newest_frame = this_frame
    oldest_frame = this_frame

    for i in range(backtrace_lines - 1):
        try:
            candidate = oldest_frame.older()
        # We catch gdb.error in case of a `gdb.error: PC not saved` case
        except (gdb.MemoryError, gdb.error):
            break

        if not candidate:
            break
        oldest_frame = candidate

    for i in range(backtrace_lines - 1):
        candidate = newest_frame.newer()
        if not candidate:
            break
        newest_frame = candidate

    frame = newest_frame
    i = 0
    bt_prefix = "%s" % pwndbg.config.backtrace_prefix
    while True:
        prefix = bt_prefix if frame == this_frame else " " * len(bt_prefix)
        prefix = f" {c.prefix(prefix)}"
        addrsz = c.address(pwndbg.ui.addrsz(frame.pc()))
        symbol = c.symbol(pwndbg.gdblib.symbol.get(int(frame.pc())))
        if symbol:
            addrsz = addrsz + " " + symbol
        line = map(str, (prefix, c.frame_label("%s%i" % (backtrace_frame_label, i)), addrsz))
        line = " ".join(line)
        result.append(line)

        if frame == oldest_frame:
            break

        frame = frame.older()
        i += 1
    return result


def context_args(with_banner=True, target=sys.stdout, width=None):
    args = pwndbg.arguments.format_args(pwndbg.aglib.disasm.one())

    # early exit to skip section if no arg found
    if not args:
        return []

    if with_banner:
        args.insert(0, pwndbg.ui.banner("arguments", target=target, width=width))

    return args


last_signal: List[str] = []

thread_status_messages = {
    "running": pwndbg.color.light_green("running"),
    "stopped": pwndbg.color.yellow("stopped"),
    "exited": pwndbg.color.gray("exited "),
}


def get_thread_status(thread):
    if thread.is_running():
        return thread_status_messages["running"]
    elif thread.is_stopped():
        return thread_status_messages["stopped"]
    elif thread.is_exited():
        return thread_status_messages["exited"]
    else:
        return "unknown"


def context_threads(with_banner=True, target=sys.stdout, width=None):
    try:
        original_thread = gdb.selected_thread()
    except SystemError:
        original_thread = None
    try:
        original_frame = gdb.selected_frame()
    except gdb.error:
        original_frame = None

    all_threads = gdb.selected_inferior().threads()[::-1]

    displayed_threads = []

    if original_thread is not None and original_thread.is_valid():
        displayed_threads.append(original_thread)

    for thread in all_threads:
        if len(displayed_threads) >= int(config_max_threads_display):
            break

        if thread.is_valid() and thread is not original_thread:
            displayed_threads.append(thread)

    num_threads_not_shown = len(all_threads) - len(displayed_threads)

    if len(displayed_threads) < 2:
        return []

    out = [pwndbg.ui.banner(f"threads ({len(all_threads)} total)", target=target, width=width)]
    max_name_length = 0

    for thread in displayed_threads:
        name = thread.name or ""
        if len(name) > max_name_length:
            max_name_length = len(name)

    for thread in filter(lambda t: t.is_valid(), displayed_threads):
        selected = " ►" if thread is original_thread else "  "
        name = thread.name if thread.name is not None else ""
        padding = max_name_length - len(name)
        status = get_thread_status(thread)

        line = (
            f" {selected} {thread.global_num}\t"
            f'"{pwndbg.color.cyan(name)}" '
            f'{" " * padding}'
            f"{status}: "
        )

        if thread.is_stopped():
            thread.switch()
            pc = gdb.selected_frame().pc()

            pc_colored = M.get(pc)
            symbol = pwndbg.gdblib.symbol.get(pc)

            line += f"{pc_colored}"
            if symbol:
                line += f" <{pwndbg.color.bold(pwndbg.color.green(symbol))}> "

        out.append(line)

    if num_threads_not_shown:
        out.append(
            pwndbg.lib.tips.color_tip(
                f"Not showing {num_threads_not_shown} thread(s). Use `set context-max-threads <number of threads>` to change this."
            )
        )

    if original_thread is not None and original_thread.is_valid():
        original_thread.switch()
    if original_frame is not None and original_frame.is_valid():
        original_frame.select()

    return out


def save_signal(signal) -> None:
    global last_signal
    last_signal = result = []

    if isinstance(signal, gdb.ExitedEvent):
        # Booooo old gdb
        if hasattr(signal, "exit_code"):
            result.append(message.exit("Exited: %r" % signal.exit_code))

    elif isinstance(signal, gdb.SignalEvent):
        msg = f"Program received signal {signal.stop_signal}"

        if signal.stop_signal == "SIGSEGV":
            # When users use rr (https://rr-project.org or https://github.com/mozilla/rr)
            # we can't access $_siginfo, so lets just show current pc
            # see also issue 476
            if _is_rr_present():
                msg += " (current pc: %#x)" % pwndbg.gdblib.regs.pc
            else:
                try:
                    si_addr = gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr")
                    msg += " (fault address %#x)" % int(si_addr or 0)
                except gdb.error:
                    pass
        result.append(message.signal(msg))

    elif isinstance(signal, gdb.BreakpointEvent):
        for bkpt in signal.breakpoints:
            result.append(message.breakpoint(f"Breakpoint {(bkpt.location)}"))


gdb.events.cont.connect(save_signal)
gdb.events.stop.connect(save_signal)
gdb.events.exited.connect(save_signal)


def context_signal():
    return last_signal


context_sections = {
    "r": context_regs,
    "d": context_disasm,
    "a": context_args,
    "c": context_code,
    "s": context_stack,
    "b": context_backtrace,
    "e": context_expressions,
    "g": context_ghidra,
    "h": context_heap_tracker,
    "t": context_threads,
}


@pwndbg.lib.cache.cache_until("forever")
def _is_rr_present() -> bool:
    """
    Checks whether rr project is present (so someone launched e.g. `rr replay <some-recording>`)
    """

    # this is ugly but I couldn't find a better way to do it
    # feel free to refactor it
    globals_list_literal_str = gdb.execute("python print(list(globals().keys()))", to_string=True)
    interpreter_globals = ast.literal_eval(globals_list_literal_str)

    return "RRCmd" in interpreter_globals and "RRWhere" in interpreter_globals
