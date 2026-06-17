from __future__ import annotations

from collections import defaultdict

from capstone6pwndbg import *  # noqa: F403

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.vmmap
import pwndbg.color
import pwndbg.color.context as ctx_color
import pwndbg.color.disasm
import pwndbg.color.theme
import pwndbg.commands.comments
import pwndbg.lib.config
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.disasm.instruction import SplitType
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import blue
from pwndbg.color import green
from pwndbg.color import light_gray
from pwndbg.color import light_green
from pwndbg.color import light_purple
from pwndbg.color import light_red
from pwndbg.color import message
from pwndbg.color import purple
from pwndbg.color import red
from pwndbg.color import rjust_colored
from pwndbg.color import white
from pwndbg.color import yellow


def ljust_padding(lst: list[str]) -> tuple[list[str], int]:
    """
    Returns (list of padded strings, max length of string)
    """
    longest_len = max(map(len, lst)) if lst else 0
    return [s.ljust(longest_len) for s in lst], longest_len


c = ColorConfig(
    "nearpc",
    [
        ColorParamSpec("symbol", "normal", "color for nearpc command (symbol)"),
        ColorParamSpec("address", "normal", "color for nearpc command (address)"),
        ColorParamSpec("prefix", "none", "color for nearpc command (prefix marker)"),
        ColorParamSpec("breakpoint", "red", "color for nearpc command (breakpoint marker)"),
        ColorParamSpec("syscall-name", "red", "color for nearpc command (resolved syscall name)"),
        ColorParamSpec("argument", "bold", "color for nearpc command (target argument)"),
        ColorParamSpec(
            "integration-comments", "bold", "color for nearpc command (integration comments)"
        ),
        ColorParamSpec("branch-marker", "normal", "color for nearpc command (branch marker line)"),
    ],
)

# `pwndbg.arguments` imports `c` from this module.
import contextlib

import pwndbg.arguments

nearpc_branch_marker = pwndbg.color.theme.add_param(
    "nearpc-branch-marker", "    ↓", "branch marker line for nearpc command"
)
nearpc_branch_marker_contiguous = pwndbg.color.theme.add_param(
    "nearpc-branch-marker-contiguous",
    " ",
    "contiguous branch marker line for nearpc command",
)
pwndbg.color.theme.add_param("highlight-pc", True, "whether to highlight the current instruction")
pwndbg.color.theme.add_param("highlight-breakpoints", True, "whether to highlight breakpoints")
pwndbg.color.theme.add_param("nearpc-prefix", "►", "prefix marker for nearpc command")
pwndbg.color.theme.add_param(
    "nearpc-breakpoint-prefix", "b+", "breakpoint marker for nearpc command"
)
pwndbg.color.theme.add_param(
    "nearpc-current-breakpoint-prefix",
    "b►",
    "marker for when current instruction is at a breakpoint",
)
pwndbg.config.add_param("left-pad-disasm", True, "whether to left-pad disassembly")
show_args = pwndbg.config.add_param(
    "nearpc-show-args", True, "whether to show call arguments below instruction"
)
# show_comments = pwndbg.config.add_param(
#     "nearpc-integration-comments",
#     True,
#     "whether to show comments from integration provider",
# )
show_opcode_bytes = pwndbg.config.add_param(
    "nearpc-num-opcode-bytes",
    0,
    "number of opcode bytes to print for each instruction",
    param_class=pwndbg.lib.config.PARAM_ZUINTEGER,
)
opcode_separator_bytes = pwndbg.config.add_param(
    "nearpc-opcode-separator-bytes",
    1,
    "number of spaces between opcode bytes",
    param_class=pwndbg.lib.config.PARAM_ZUINTEGER,
)


class JumpRange:
    start: int
    end: int
    forward: bool

    min: int
    max: int

    def __init__(self, s: int, e: int):
        self.start = s
        self.end = e

        self.forward = self.start < self.end

        self.min = min(self.start, self.end)
        self.max = max(self.start, self.end)

    def contains(self, address: int) -> bool:
        return self.min <= address <= self.max

    def overlaps(self, other: JumpRange) -> bool:
        return max(self.min, other.min) <= min(self.max, other.max)

    def __repr__(self) -> str:
        return f"JumpRange({hex(self.start)}, {hex(self.end)})"


COLUMNS_ALLOCATED_FOR_BRANCH_VISUALIZATION = 20

# Symbols used in branch visualization
TOP_LEFT_CORNER = "┌"
BOT_LEFT_CORNER = "└"
HORZ_SYMBOL = "─"
VERT_SYMBOL = "│"
START_SYMBOL = "<"
END_SYMBOL = ">"
DOTTED_VERTICAL = "╎"
UP_SYMBOL = "▲"

offset_to_color_map = {
    0: white,
    1: red,
    2: green,
    3: purple,
    4: blue,
    5: white,
    6: yellow,
    7: light_red,
    8: light_purple,
    9: light_gray,
    10: light_green,
}


# Allows to the branch visualization work across repeated uses of nearpc
# Maps the jump range to the id it was given.
last_run_ids: dict[JumpRange, int] = {}


def colorize_branch_vis_line(offset: int, string: str):
    return offset_to_color_map.get(offset, lambda x: str(x))(string)


def preprocess_branch_visualization(
    instructions: list[PwndbgInstruction], repeat: bool
) -> tuple[dict[int, list[JumpRange]], dict[JumpRange, int], int]:
    """
    Returns (pair_map dictionary,pair_id dictionary, maximum_pair_id)
    """
    global last_run_ids

    jumps: list[JumpRange] = []

    # Map of every address to every jump range it belongs in
    pair_map: dict[int, list[JumpRange]] = defaultdict(list)

    # For a given jump range, it has a unique ID compared to every other jump range it overlaps with
    # This allows us to display each jump range at a different visual offset
    pair_id: dict[JumpRange, int] = defaultdict(lambda: -1)

    # -2 because at least two columns are needed: one for the "<" or ">" branch ends, and one for pair id 0
    maximum_pair_id = COLUMNS_ALLOCATED_FOR_BRANCH_VISUALIZATION - 2

    # Find all instructions eligible for branch visualization
    for instruction in instructions:
        if instruction.jump_like and instruction.has_jump_target and not instruction.call_like:
            jumps.append(JumpRange(instruction.address, instruction.target))

    # Of the jumpranges we processed last time, which ones do we keep? Relevant for repeat nearpc
    continued_ranges: set[JumpRange] = set()

    # Population structure mapping every address to each jump range it belongs to
    for instruction in instructions:
        for pair in jumps:
            if pair.contains(instruction.address):
                pair_map[instruction.address].append(pair)

        if repeat:
            for pair, y in last_run_ids.items():
                if pair.contains(instruction.address):
                    pair_map[instruction.address].append(pair)
                    continued_ranges.add(pair)

    if repeat:
        for pair in continued_ranges:
            pair_id[pair] = last_run_ids[pair]
            jumps.append(pair)

    # Preprocess each pair to assign a unique ID to all overlapping ranges.
    for pair1 in jumps:
        # If this was from a repeat range, ignore it
        if pair_id[pair1] >= 0:
            continue

        cur_offset = 0
        for pair2 in jumps:
            if pair1 == pair2:
                continue

            if pair1.overlaps(pair2):
                # These two jump ranges overlap! Make sure pair1 has a larger offset!
                if pair_id[pair2] >= cur_offset:
                    cur_offset = pair_id[pair2] + 1

        # We only want a maximum number of columns
        pair_id[pair1] = min(cur_offset, maximum_pair_id)

    # Sort lists of jump ranges by ascending id
    for instruction in instructions:
        pairs = pair_map[instruction.address]
        pairs.sort(key=lambda x: pair_id[x])

    last_run_ids = pair_id

    return pair_map, pair_id, maximum_pair_id


def create_branch_visualization_strings(
    pair_map: dict[int, list[JumpRange]],
    pair_id: dict[JumpRange, int],
    maximum_pair_id: int,
    addr: int,
    is_first_address: bool,
) -> tuple[str, str]:
    """
    Returns tuple of (string, string for empty line)
    """

    if len(pair_id) == 0:
        return None, None

    # This string has ANSI colors in it
    branch_vis_string = ""

    # Length of the string ignoring ANSI color codes
    branch_vis_string_len = 0

    # This is the string placed in to the empty lines after branches
    empty_line_branch_vis_string = ""
    empty_line_branch_vis_string_len = 0

    # First, handle creating the horizontal lines (handling all the jumps that are start or end here)
    for pair in pair_map[addr]:
        # Due to preprocessing, we are iterating jump ranges at this address in order of smallest to largest id
        pair_offset = pair_id[pair]

        # The number of new columns to create in the string in this pass
        expand_amount = min(pair_offset, pair_offset - branch_vis_string_len + 1)

        # If a forward jump
        if pair.forward:
            if pair.start == addr:
                if branch_vis_string:
                    branch_vis_string = (
                        colorize_branch_vis_line(
                            pair_offset, TOP_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL
                        )
                        + branch_vis_string
                    )
                    branch_vis_string_len += 1 + expand_amount
                else:
                    branch_vis_string = colorize_branch_vis_line(
                        pair_offset,
                        TOP_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL + START_SYMBOL,
                    )
                    branch_vis_string_len += 2 + expand_amount
            elif pair.end == addr:
                if branch_vis_string:
                    branch_vis_string = (
                        colorize_branch_vis_line(
                            pair_offset, BOT_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL
                        )
                        + branch_vis_string
                    )
                    branch_vis_string_len += 1 + expand_amount
                else:
                    branch_vis_string = colorize_branch_vis_line(
                        pair_offset,
                        BOT_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL + END_SYMBOL,
                    )
                    branch_vis_string_len += 2 + expand_amount
        # Backwards jump
        elif pair.start == addr:
            if branch_vis_string:
                branch_vis_string = (
                    colorize_branch_vis_line(
                        pair_offset, BOT_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL
                    )
                    + branch_vis_string
                )
                branch_vis_string_len += 1 + expand_amount
            else:
                branch_vis_string = colorize_branch_vis_line(
                    pair_offset,
                    BOT_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL + START_SYMBOL,
                )
                branch_vis_string_len += 2 + expand_amount
        elif pair.end == addr:
            if branch_vis_string:
                branch_vis_string = (
                    colorize_branch_vis_line(
                        pair_offset, TOP_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL
                    )
                    + branch_vis_string
                )
                branch_vis_string_len += 1 + expand_amount
            else:
                branch_vis_string = colorize_branch_vis_line(
                    pair_offset,
                    TOP_LEFT_CORNER + (expand_amount) * HORZ_SYMBOL + END_SYMBOL,
                )
                branch_vis_string_len += 2 + expand_amount
        if pair_offset == maximum_pair_id:
            # We don't have any more column space for more jump ranges
            break

    # Secondly, handle the vertical lines passing through this address

    # This loop has multiple ways exit due to reaching the full column space
    # It's easier to track this with a variable.
    last_iteration = False

    for pair in pair_map[addr]:
        if last_iteration:
            break

        pair_offset = pair_id[pair]

        vert_symbol = empty_line_vert_symbol = VERT_SYMBOL

        if not pair.forward:
            empty_line_vert_symbol = DOTTED_VERTICAL
            if not is_first_address:
                vert_symbol = DOTTED_VERTICAL
            else:
                # Handle edge case: during repeated nearpc, entering a region that has a jump that goes backwards
                vert_symbol = UP_SYMBOL

        # First, handle creating the vertical lines that pass through the empty row created after branches (if it exists)
        if pair.forward:
            # If this pair ended at this address, nothing goes into the empty line after it
            if pair.end == addr:
                continue
        # If a backwards jump started here, nothing goes in the empty line after it
        elif pair.start == addr:
            continue

        if pair_offset == maximum_pair_id:
            last_iteration = True

        # A single column is always taken for the < or > characters
        target_column = pair_offset + 1

        num_empty_lines = min(target_column, target_column - empty_line_branch_vis_string_len)
        empty_line_branch_vis_string = (
            colorize_branch_vis_line(
                pair_offset,
                empty_line_vert_symbol + (" " * num_empty_lines),
            )
            + empty_line_branch_vis_string
        )
        empty_line_branch_vis_string_len += 1 + num_empty_lines

        # Now, create the string for the non-empty line
        if addr in (pair.start, pair.end):
            continue

        # Only add to the string if the space hasn't been taking by a horizontal line
        if branch_vis_string_len <= target_column:
            empty_lines = min(target_column, target_column - branch_vis_string_len)
            branch_vis_string = (
                colorize_branch_vis_line(
                    pair_offset,
                    vert_symbol + (" " * empty_lines),
                )
                + branch_vis_string
            )
            branch_vis_string_len += 1 + empty_lines

    branch_vis_string = rjust_colored(branch_vis_string, COLUMNS_ALLOCATED_FOR_BRANCH_VISUALIZATION)
    empty_line_branch_vis_string = rjust_colored(
        empty_line_branch_vis_string, COLUMNS_ALLOCATED_FOR_BRANCH_VISUALIZATION
    )

    return branch_vis_string, empty_line_branch_vis_string


def nearpc(
    pc: int | None = None,
    lines: int | None = None,
    back_lines: int = 0,
    total_lines: int | None = None,
    emulate: bool = False,
    repeat: bool = False,
    use_cache: bool = False,
    linear: bool = False,
    branch_visualization: bool = False,
    address_to_highlight: int | None = None,
    end_address: int | None = None,
) -> list[str]:
    """
    Disassemble near a specified address.

    The `linear` argument specifies if we should disassemble linearly in memory, or take jumps into account
    """
    assert address_to_highlight is None or linear, (
        "Only pc can be highlighted if linear=False"  # because we need pc_index to display emulated loops correctly
    )

    # Repeating nearpc (pressing enter) makes it show next addresses
    # (writing nearpc explicitly again will reset its state)
    if repeat:
        # TODO: It would be better to do this in the nearpc command itself, but
        # that would require a larger refactor
        pc = nearpc.next_pc

    result: list[str] = []

    if pc is not None:
        pc = pwndbg.dbg.selected_inferior().create_value(pc).cast(pwndbg.aglib.typeinfo.pvoid)

    if pc is None:
        pc = pwndbg.aglib.regs.pc

    pc = int(pc)

    if address_to_highlight is None:
        address_to_highlight = pc

    # Check whether we can even read this address
    if not pwndbg.aglib.memory.peek(pc):
        result.append(message.error(f"Invalid address {pc:#x}"))

    if lines is None:
        lines = int(pwndbg.config.nearpc_lines)

    # # Load source data if it's available
    # pc_to_linenos = collections.defaultdict(lambda: [])
    # lineno_to_src = {}
    # frame = gdb.selected_frame()
    # if frame:
    #     sal = frame.find_sal()
    #     if sal:
    #         symtab = sal.symtab
    #         objfile = symtab.objfile
    #         sourcefilename = symtab.filename
    #         with open(sourcefilename, 'r') as sourcefile:
    #             lineno_to_src = {i:l for i,l in enumerate(sourcefile.readlines())}

    #         for line in symtab.linetable():
    #             pc_to_linenos[line.pc].append(line.line)

    instructions, index_of_pc = pwndbg.aglib.disasm.disassembly.near(
        pc,
        forward_count=lines,
        backward_count=back_lines,
        total_count=total_lines,
        emulate=emulate,
        show_prev_insns=not repeat,
        use_cache=use_cache,
        linear=linear,
        end_address=end_address,
    )

    # If doing branch visualization, preprocess some datastructures
    if branch_visualization:
        pair_map, pair_id, maximum_pair_id = preprocess_branch_visualization(instructions, repeat)

    if pwndbg.aglib.memory.peek(pc) and not instructions:
        result.append(message.error(f"Invalid instructions at {pc:#x}"))

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.aglib.vmmap.find(pc)

    # Gather all addresses and symbols for each instruction
    # Ex: <main+43>
    symbols = [pwndbg.aglib.symbol.resolve_addr(i.address) for i in instructions]
    addresses: list[str] = [f"{i.address:#x}" for i in instructions]

    nearpc.next_pc = instructions[-1].address + instructions[-1].size if instructions else 0

    # Format the symbol name for each instruction
    symbols = [f"<{sym}> " if sym else "" for sym in symbols]

    # Pad out all of the symbols and addresses
    if pwndbg.config.left_pad_disasm:
        symbols, symbols_max_length = ljust_padding(symbols)
        addresses, addresses_max_length = ljust_padding(addresses)
    else:
        symbols_max_length = max(map(len, symbols)) if symbols else 0
        addresses_max_length = max(map(len, addresses)) if addresses else 0

    assembly_strings = pwndbg.color.disasm.instructions_and_padding(instructions, linear=linear)

    breakpoint_locations = pwndbg.dbg.breakpoint_locations()

    prefix_sign = pwndbg.config.nearpc_prefix

    # Prefix for instruction at the current program counter
    current_insn_prefix = f" {prefix_sign}"
    current_insn_prefix = c.prefix(current_insn_prefix)

    # Prefix for non-breakpoints and non-current instructions
    default_prefix = " " * (len(prefix_sign) + 1)
    default_prefix = c.prefix(default_prefix)

    # Prefix for when instruction is a breakpoint, but not at the current instruction
    breakpoint_sign = pwndbg.config.nearpc_breakpoint_prefix
    breakpoint_prefix = breakpoint_sign.ljust(len(prefix_sign) + 1)
    breakpoint_prefix = c.breakpoint(breakpoint_prefix)

    # Prefix for when current instruction is a breakpoint
    current_breakpoint_sign = pwndbg.config.nearpc_current_breakpoint_prefix
    current_insn_breakpoint_prefix = current_breakpoint_sign.ljust(len(prefix_sign) + 1)
    current_insn_breakpoint_prefix = c.breakpoint(c.prefix(current_insn_breakpoint_prefix))

    # Print out each instruction
    for i, (address_str, symbol, instruction, asm) in enumerate(
        zip(addresses, symbols, instructions, assembly_strings)
    ):
        # Show a prefix for the instruction at `address_to_highlight`. Don't show it while in repeat-mode
        # or when showing current instruction for the second time
        highlight_line = (
            instruction.address == address_to_highlight
            and not repeat
            and (linear or i == index_of_pc)
        )
        instruction_has_breakpoint = instruction.address in breakpoint_locations

        is_non_pc_breakpoint = False
        if highlight_line:
            if instruction_has_breakpoint:
                prefix = current_insn_breakpoint_prefix
            else:
                prefix = current_insn_prefix
        elif instruction_has_breakpoint:
            # If the instruction is not the current instruction and a breakpoint,
            # show the breakpoint sign
            prefix = breakpoint_prefix
            is_non_pc_breakpoint = True
        else:
            prefix = default_prefix

        # If this instruction is a breakpoint and not the current pc, highlight it.
        if is_non_pc_breakpoint and pwndbg.config.highlight_breakpoints:
            address_str = c.breakpoint(address_str)
            symbol = c.breakpoint(symbol)
        # Colorize address and symbol if not highlighted
        # symbol is fetched from gdb and it can be e.g. '<main+8>'
        # In case there are duplicate instances of an instruction (tight loop),
        # ones that the instruction pointer is not at stick out a little, to indicate the repetition
        elif not highlight_line:
            address_str = c.address(address_str)
            symbol = c.symbol(symbol)
        else:
            # If this instruction is the one the PC is at.
            # In case of tight loops, with emulation we may display the same instruction multiple times.
            # Only highlight current instance, not past or future times.
            address_str = ctx_color.highlight(address_str)
            symbol = ctx_color.highlight(symbol)

        opcodes = ""
        if show_opcode_bytes > 0:
            opcodes = (opcode_separator_bytes * " ").join(
                f"{c:02x}" for c in instruction.bytes[: int(show_opcode_bytes)]
            )
            # Must add +3 at minimum, due to truncated instructions adding "..."
            align = show_opcode_bytes * 2 + 3
            if opcode_separator_bytes > 0:
                # add the length of the maximum number of separators to the alignment
                align += (show_opcode_bytes - 1) * opcode_separator_bytes  # type: ignore[operator]
            if len(instruction.bytes) > show_opcode_bytes:
                opcodes += pwndbg.color.gray("...")
                # the length of gray("...") is 12, so we need to add extra 9 (12-3) alignment length for the invisible characters
                align += 9  # len(pwndbg.color.gray(""))
            opcodes = opcodes.ljust(align)
            if highlight_line:
                opcodes = ctx_color.highlight(opcodes)

        if branch_visualization:
            branch_vis_string, empty_line_branch_vis_string = create_branch_visualization_strings(
                pair_map, pair_id, maximum_pair_id, instruction.address, i == 0
            )
        else:
            branch_vis_string = None
            empty_line_branch_vis_string = ""

        # Example line:
        # ► 0x7ffff7f1aeb6 0f bd c0    <__strrchr_avx2+70>    bsr    eax, eax
        # prefix        = ►
        # address_str   = 0x555555556030
        # opcodes       = 0f bd c0                  Opcodes are enabled with the 'nearpc-num-opcode-bytes' setting
        # symbol        = <__strrchr_avx2+70>
        # asm           = bsr    eax, eax           (jump target/annotation would go here too)

        printable_elements = list(
            filter(None, (prefix, address_str, opcodes, symbol, branch_vis_string, asm))
        )

        line = " ".join(printable_elements)

        if branch_visualization and branch_vis_string:
            # Adjust the padding for the branch visualization string for the empty line
            branch_vis_padding = (
                -1  # -1 because there's a space between all printable_elements, so n-1 spaces
                + len(printable_elements)
                + len(prefix_sign)
                + addresses_max_length
                + len(opcodes)
                + symbols_max_length
            )
            empty_line_branch_vis_string = rjust_colored(
                empty_line_branch_vis_string,
                branch_vis_padding + COLUMNS_ALLOCATED_FOR_BRANCH_VISUALIZATION,
            )
        # FIXME(provider, integration): can we look into doing this on the decompiler side?
        # if show_comments:
        #     # Pull comments from integration if possible
        #     result += [
        #         " "
        #         * (len(pwndbg.color.unstylize(line)) - len(pwndbg.color.unstylize(asm).lstrip()))
        #         + c.integration_comments(x)
        #         for x in pwndbg.dintegration.provider.get_comment_lines(instr.address)
        #     ]

        # For Comment Function
        with contextlib.suppress(Exception):
            line += " " * 10 + ctx_color.comment(
                pwndbg.commands.comments.file_lists[pwndbg.aglib.proc.exe()][
                    hex(instruction.address)
                ]
            )

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        if show_args:
            result.extend(
                f"{'':>8}{arg}" for arg in pwndbg.arguments.format_args(instruction=instruction)
            )

        # If this instruction deserves a down arrow to indicate a taken branch
        if instruction.split == SplitType.BRANCH_TAKEN:
            result.append(empty_line_branch_vis_string + c.branch_marker(f"{nearpc_branch_marker}"))

        # Otherwise if it's a branch and it *is* contiguous, just put an empty line.
        elif instruction.split == SplitType.BRANCH_NOT_TAKEN:
            if nearpc_branch_marker_contiguous:
                if empty_line_branch_vis_string:
                    result.append(empty_line_branch_vis_string)
                else:
                    result.append(f"{nearpc_branch_marker_contiguous}")

    return result


nearpc.next_pc = 0
