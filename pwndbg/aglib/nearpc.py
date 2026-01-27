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
from pwndbg.aglib.disasm.instruction import SplitType
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import blue
from pwndbg.color import cyan
from pwndbg.color import green
from pwndbg.color import light_gray
from pwndbg.color import light_green
from pwndbg.color import light_purple
from pwndbg.color import light_red
from pwndbg.color import message
from pwndbg.color import purple
from pwndbg.color import red
from pwndbg.color import rjust_colored
from pwndbg.color import strip
from pwndbg.color import white


def ljust_padding(lst):
    longest_len = max(map(len, lst)) if lst else 0
    return [s.ljust(longest_len) for s in lst]


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


def nearpc(
    pc: int = None,
    lines: int = None,
    back_lines: int = 0,
    total_lines: int = None,
    emulate=False,
    repeat=False,
    use_cache=False,
    linear=False,
    branch_visualization=False,
    where: int = 0,
) -> list[str]:
    """
    Disassemble near a specified address.

    The `linear` argument specifies if we should disassemble linearly in memory, or take jumps into account
    """

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
    )

    if branch_visualization:
        jumps: list[JumpRange] = []

        ## The following section contain setup for branch visualization logic
        # Map of address to pairs
        pair_map: dict[int, list[JumpRange]] = defaultdict(list)
        pair_offsets: dict[JumpRange, int] = defaultdict(lambda: -1)

        # Map each address to the list of jump ranges that contain it
        for instruction in instructions:
            if instruction.jump_like and instruction.has_jump_target and not instruction.call_like:
                jumps.append(JumpRange(instruction.address, instruction.target))

        # Generate map to address to jump it belongs in
        for instruction in instructions:
            for pair in jumps:
                if pair.contains(instruction.address):
                    pair_map[instruction.address].append(pair)

        # Preprocess each pair to assign a unique ID to all overlapping ranges
        for pair1 in jumps:
            # TODO: don't default to -1! Default to 0 if no overlaps?
            cur_offset = -1
            for pair2 in jumps:
                if pair1 == pair2:
                    continue

                if pair1.overlaps(pair2):
                    if pair_offsets[pair2] >= cur_offset:
                        # TODO: this is safe, but we could find a "hole" in between the lines where this offset could go
                        # Basically, for all the pairs this overlaps with, pick the highest
                        # value not in the list of those id's.
                        cur_offset = pair_offsets[pair2] + 1

            pair_offsets[pair1] = cur_offset

        # Sort lists of jump ranges by ascending id
        for instruction in instructions:
            pairs = pair_map[instruction.address]
            pairs.sort(key=lambda x: pair_offsets[x])
            # print([pair_offsets[x] for x in pairs])

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
    if pwndbg.config.left_pad_disasm and not repeat:
        symbols = ljust_padding(symbols)
        addresses = ljust_padding(addresses)

    assembly_strings = pwndbg.color.disasm.instructions_and_padding(instructions)

    breakpoint_locations = pwndbg.dbg.breakpoint_locations()

    prefix_sign = pwndbg.config.nearpc_prefix
    current_insn_prefix = f" {prefix_sign}"
    current_insn_prefix = c.prefix(current_insn_prefix)
    default_prefix = " " * (len(prefix_sign) + 1)
    default_prefix = c.prefix(default_prefix)

    breakpoint_sign = pwndbg.config.nearpc_breakpoint_prefix
    breakpoint_prefix = breakpoint_sign.ljust(len(prefix_sign) + 1)
    breakpoint_prefix = c.breakpoint(breakpoint_prefix)

    # Print out each instruction
    for i, (address_str, symbol, instr, asm) in enumerate(
        zip(addresses, symbols, instructions, assembly_strings)
    ):
        # Show prefix only on the specified address and don't show it while in repeat-mode
        # or when showing current instruction for the second time
        show_prefix = instr.address == pc and not repeat and i == index_of_pc
        is_breakpoint = False
        if show_prefix:
            prefix = current_insn_prefix
        elif instr.address in breakpoint_locations:
            # If the instruction is not the current instruction and a breakpoint,
            # show the breakpoint sign
            prefix = breakpoint_prefix
            is_breakpoint = True
        else:
            prefix = default_prefix

        # If this instruction is a breakpoint and not the current pc, highlight it.
        if is_breakpoint and pwndbg.config.highlight_breakpoints:
            address_str = c.breakpoint(address_str)
            symbol = c.breakpoint(symbol)
        # Colorize address and symbol if not highlighted
        # symbol is fetched from gdb and it can be e.g. '<main+8>'
        # In case there are duplicate instances of an instruction (tight loop),
        # ones that the instruction pointer is not at stick out a little, to indicate the repetition
        elif not pwndbg.config.highlight_pc or instr.address != pc or repeat:
            address_str = c.address(address_str)
            symbol = c.symbol(symbol)
        elif pwndbg.config.highlight_pc and i == index_of_pc:
            # If this instruction is the one the PC is at.
            # In case of tight loops, with emulation we may display the same instruction multiple times.
            # Only highlight current instance, not past or future times.
            address_str = ctx_color.highlight(address_str)
            symbol = ctx_color.highlight(symbol)

        # If this instruction performs a memory access operation, we should tell
        # the user anything we can figure out about the memory it's trying to
        # access.
        # mem_access = ""
        if instr.address == pc and False:
            accesses = []
            for operand in instr.operands:
                if operand.type != CS_OP_MEM:
                    continue
                address = operand.mem.disp

                base = operand.mem.base
                if base > 0:
                    address += pwndbg.aglib.regs.read_reg(instr.reg_name(base))

                vmmap = pwndbg.aglib.vmmap.get()
                page = next((page for page in vmmap if address in page), None)
                if page is None:
                    # This is definetly invalid. Don't even bother checking
                    # any other conditions.
                    accesses.append(f"[X] {address:#x}")
                    continue

                if operand.access == CS_AC_READ and not page.read:
                    # Tried to read from a page we can't read.
                    accesses.append(f"[X] {address:#x}")
                    continue
                if operand.access == CS_AC_WRITE and not page.write:
                    # Tried to write to a page we can't write.
                    accesses.append(f"[X] {address:#x}")
                    continue

                # At this point, we know the operation is legal, but we don't
                # know where it's going yet. It could be going to either memory
                # managed by libc or memory managed by the program itself.

                if not pwndbg.aglib.heap.current.is_initialized():
                    # The libc heap hasn't been initialized yet. There's not a
                    # lot that we can say beyond this point.
                    continue
                allocator = pwndbg.aglib.heap.current

                heap = pwndbg.aglib.heap.ptmalloc.Heap(address)
                chunk = None
                for ch in heap:
                    # Find the chunk in this heap the corresponds to the address
                    # we're trying to access.
                    offset = address - ch.address
                    if offset >= 0 and offset < ch.real_size:
                        chunk = ch
                        break
                if chunk is None:
                    # The memory for this chunk is not managed by libc. We can't
                    # reason about it.
                    accesses.append(f"[?] {address:#x}")
                    continue

                # Scavenge through all of the bins in the current allocator.
                # Bins track free chunks, so, whether or not we can find the
                # chunk we're trying to access in a bin will tells us whether
                # this access is a UAF.
                bins_list = [
                    allocator.fastbins(chunk.arena.address),
                    allocator.smallbins(chunk.arena.address),
                    allocator.largebins(chunk.arena.address),
                    allocator.unsortedbin(chunk.arena.address),
                ]
                if allocator.has_tcache():
                    bins_list.append(allocator.tcachebins(None))

                bins_list = [x for x in bins_list if x is not None]
                for bins in bins_list:
                    if bins.contains_chunk(chunk.real_size, chunk.address):
                        # This chunk is free. This is a UAF.
                        accesses.append(f"[UAF] {address:#x}")
                        continue
            # mem_access = " ".join(accesses)

        opcodes = ""
        if show_opcode_bytes > 0:
            opcodes = (opcode_separator_bytes * " ").join(
                f"{c:02x}" for c in instr.bytes[: int(show_opcode_bytes)]
            )
            # Must add +3 at minimum, due to truncated instructions adding "..."
            align = show_opcode_bytes * 2 + 3
            if opcode_separator_bytes > 0:
                # add the length of the maximum number of separators to the alignment
                align += (show_opcode_bytes - 1) * opcode_separator_bytes  # type: ignore[operator]
            if len(instr.bytes) > show_opcode_bytes:
                opcodes += pwndbg.color.gray("...")
                # the length of gray("...") is 12, so we need to add extra 9 (12-3) alignment length for the invisible characters
                align += 9  # len(pwndbg.color.gray(""))
            opcodes = opcodes.ljust(align)
            if pwndbg.config.highlight_pc and i == index_of_pc:
                opcodes = ctx_color.highlight(opcodes)

        # Example line:
        # ► 0x7ffff7f1aeb6 0f bd c0    <__strrchr_avx2+70>    bsr    eax, eax
        # prefix        = ►
        # address_str   = 0x555555556030
        # opcodes       = 0f bd c0                  Opcodes are enabled with the 'nearpc-num-opcode-bytes' setting
        # symbol        = <__strrchr_avx2+70>
        # asm           = bsr    eax, eax           (jump target/annotation would go here too)

        if branch_visualization:
            TOP_LEFT_CORNER = "┌"
            BOT_LEFT_CORNER = "└"
            HORZ_SYMBOL = "─"
            VERT_SYMBOL = "│"
            START_SYMBOL = "<"
            END_SYMBOL = ">"
            DOTTED_VERTICAL = "╎"

            PADDING_FOR_FLOW = 15

            addr = instr.address
            # Compute lines

            offset_to_color_map = {
                0: white,
                1: red,
                2: green,
                3: blue,
                4: white,
                5: purple,
                6: cyan,
                7: light_red,
                8: light_purple,
                9: light_gray,
                10: light_green,
            }

            def colorize(offset: int, string: str):
                return offset_to_color_map.get(offset, lambda x: str(x))(string)

            # Find the one that starts here
            flow = ""
            for pair in pair_map[addr]:
                offset = pair_offsets[pair] + 1

                amount = min(offset, offset - len(strip(flow)))

                # If a forward jump
                if pair.forward:
                    if pair.start == addr:
                        if flow:
                            flow = colorize(offset, TOP_LEFT_CORNER + (amount) * HORZ_SYMBOL) + flow
                        else:
                            flow = colorize(
                                offset, TOP_LEFT_CORNER + (amount) * HORZ_SYMBOL + START_SYMBOL
                            )
                    elif pair.end == addr:
                        if flow:
                            # flow = colorize(offset,strip(flow)[:-1] + END_SYMBOL)
                            flow = colorize(offset, BOT_LEFT_CORNER + (amount) * HORZ_SYMBOL) + flow
                        else:
                            flow = colorize(
                                offset, BOT_LEFT_CORNER + (amount) * HORZ_SYMBOL + END_SYMBOL
                            )
                else:
                    # Backwards jump
                    if pair.start == addr:
                        if flow:
                            flow = colorize(offset, BOT_LEFT_CORNER + (amount) * HORZ_SYMBOL) + flow
                        else:
                            flow = colorize(
                                offset, BOT_LEFT_CORNER + (amount) * HORZ_SYMBOL + START_SYMBOL
                            )
                    elif pair.end == addr:
                        if flow:
                            # flow = colorize(offset,strip(flow)[:-1] + END_SYMBOL)
                            flow = colorize(offset, TOP_LEFT_CORNER + (amount) * HORZ_SYMBOL) + flow
                        else:
                            flow = colorize(
                                offset, TOP_LEFT_CORNER + (amount) * HORZ_SYMBOL + END_SYMBOL
                            )

            # repeat_flow is the string placed in to the empty lines after branches
            # It contains no --> or <--
            repeat_flow = ""
            for pair in pair_map[addr]:
                offset = pair_offsets[pair] + 1
                spacing_offset = offset + 1

                local_vert_symbol = VERT_SYMBOL
                if not pair.forward:
                    local_vert_symbol = DOTTED_VERTICAL

                if pair.forward:
                    # If ending here, don't add to repeat flow
                    if pair.end == addr:
                        continue
                else:
                    # Backwards jmp, at start
                    if pair.start == addr:
                        # Not when going backwards!
                        continue

                repeat_flow = (
                    colorize(
                        offset,
                        local_vert_symbol
                        + (" " * (min(spacing_offset, spacing_offset - len(strip(repeat_flow))))),
                    )
                    + repeat_flow
                )

                if pair.start == addr or pair.end == addr:
                    continue

                if len(strip(flow)) <= spacing_offset:
                    flow = (
                        colorize(
                            offset,
                            local_vert_symbol
                            + " " * (min(spacing_offset, spacing_offset - len(strip(flow)))),
                        )
                        + flow
                    )

            flow = rjust_colored(flow, PADDING_FOR_FLOW)
            repeat_flow = rjust_colored(repeat_flow, PADDING_FOR_FLOW)
        else:
            flow = None
            repeat_flow = ""

        # mem_access was on this list, but not used due to the `and False` in the code that sets it above
        # line = " ".join(filter(None, (flow, prefix, address_str, opcodes, symbol, asm)))

        if where == 0:
            line = " ".join(filter(None, (flow, prefix, address_str, opcodes, symbol, asm)))
        else:
            line = " ".join(filter(None, (prefix, address_str, opcodes, symbol, flow, asm)))
            longest_len = len(strip(prefix)) + max(map(len, symbols)) + max(map(len, addresses))
            repeat_flow = rjust_colored(repeat_flow, longest_len + PADDING_FOR_FLOW + 3)
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
        try:
            line += " " * 10 + ctx_color.comment(
                pwndbg.commands.comments.file_lists[pwndbg.aglib.proc.exe()][hex(instr.address)]
            )
        except Exception:
            pass

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        if show_args:
            result.extend(
                f"{'':>8}{arg}" for arg in pwndbg.arguments.format_args(instruction=instr)
            )

        # If this instruction deserves a down arrow to indicate a taken branch
        if instr.split == SplitType.BRANCH_TAKEN:
            result.append(repeat_flow + c.branch_marker(f"{nearpc_branch_marker}"))

        # Otherwise if it's a branch and it *is* contiguous, just put an empty line.
        elif instr.split == SplitType.BRANCH_NOT_TAKEN:
            if nearpc_branch_marker_contiguous:
                if repeat_flow:
                    result.append(repeat_flow)
                else:
                    result.append(f"{nearpc_branch_marker_contiguous}")

    return result


nearpc.next_pc = 0
