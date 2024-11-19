from __future__ import annotations

from typing import List

import pwndbg.aglib.nearpc
import pwndbg.aglib.regs
import pwndbg.chain
import pwndbg.color.context as C
from pwndbg.aglib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color.message import on

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)


# Returns colorized instructions assembly and operands, and checkmark if branch is taken
#  Example: `✔ je     _IO_file_xsputn+341`. Inline symbol replacements made. No annotation or branch targets shown.
def one_instruction(ins: PwndbgInstruction) -> str:
    asm = ins.asm_string

    # Highlight the current line if enabled
    if pwndbg.config.highlight_pc and ins.address == pwndbg.aglib.regs.pc:
        asm = C.highlight(asm)

    is_call_or_jump = ins.groups & ALL_JUMP_GROUPS

    # Style the instruction mnemonic if it's a call/jump instruction.
    if is_call_or_jump:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    # If we know the conditional is taken, mark it as taken.
    if ins.condition == InstructionCondition.TRUE or ins.is_conditional_jump_taken:
        asm = on("✔ ") + asm
    else:
        asm = "  " + asm

    return asm


MIN_SPACING = 5
WHITESPACE_LIMIT = 20


# To making the padding visually nicer, the following padding scheme is used for annotations:
# All instructions in a group will have the same amount of left-adjusting spaces, so they are aligned.
# A group is defined as a sequence of instructions surrounded by instructions that can change the instruction pointer.
def instructions_and_padding(instructions: List[PwndbgInstruction]) -> List[str]:
    result: List[str] = []

    cur_padding_len = None

    # Stores intermediate padding results so we can do a final pass to clean up edges and jagged parts
    # None if padding doesn't apply to the instruction
    paddings: List[int | None] = []

    # Used for padding. List of groups.
    # Each group is a list of index into paddings list
    groups: List[List[int]] = []

    current_group: List[int] = []

    for i, (ins, asm) in enumerate(zip(instructions, (one_instruction(i) for i in instructions))):
        if ins.has_jump_target:
            sym = ins.target_string

            asm = f"{ljust_colored(asm, 36)} <{sym}>"

            paddings.append(None)
            if current_group:
                groups.append(current_group)
                current_group = []
        else:
            if ins.syscall is not None:
                asm += f" <{pwndbg.aglib.nearpc.c.syscall_name('SYS_' + ins.syscall_name)}>"

            # Padding the string for a nicer output
            # This path calculates the padding for each instruction - even if there we don't have annotations for it.
            # This allows groups to have uniform padding, even if some of the instructions don't have annotations
            current_group.append(i)

            raw_len = len(strip(asm))

            if cur_padding_len is None:
                cur_padding_len = raw_len + MIN_SPACING
            elif cur_padding_len - raw_len < MIN_SPACING:
                # Annotations are getting too close to the disasm, push them to the right again
                cur_padding_len = raw_len + MIN_SPACING
            else:
                # This path allows the padding to be smaller again
                # If the instruction has too much whitespace, put the annotation more to the left
                # Make sure there is an instruction after this one, and it's not a branch. Otherwise, maintain current indentation.
                if (
                    i < len(instructions) - 1
                    and not instructions[i + 1].has_jump_target
                    and cur_padding_len - raw_len > WHITESPACE_LIMIT
                ):
                    cur_padding_len = raw_len + MIN_SPACING

            # Give the padding to the instruction, so we can reuse it in the future
            if ins.annotation:
                if ins.annotation_padding is not None:
                    cur_padding_len = ins.annotation_padding
                else:
                    ins.annotation_padding = cur_padding_len

            paddings.append(cur_padding_len)

        result.append(asm)

    if current_group:
        groups.append(current_group)

    # Make instructions in each group aligned uniformly
    for group in groups:
        if len(group) == 0:
            continue

        # Find minimum spacing
        min_padding = max(paddings[index] for index in group)

        # Make all the paddings in this group have the same padding
        for index in group:
            paddings[index] = min_padding

    final_result = []

    # Final pass to apply final paddings to make alignment of blocks of instructions cleaner
    for i, (ins, asm, padding) in enumerate(zip(instructions, result, paddings)):
        # Padding being None implies a jump target - this is already baked into "asm"
        if ins.annotation and padding is not None:
            asm = f"{ljust_colored(asm, padding)}{ins.annotation}"

        final_result.append(asm)

    return final_result
