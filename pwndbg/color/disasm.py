from __future__ import annotations

import capstone

import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.color.syntax_highlight as H
import pwndbg.disasm.jump
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color.message import on
from pwndbg.disasm.instruction import PwndbgInstruction

# The amount of whitespace between instructions and the annotation, by default
pwndbg.gdblib.config.add_param(
    "disasm-annotations-whitespace-padding",
    8,
    """
number of spaces between assembly operands and annotations
""",
)


capstone_branch_groups = {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP}

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)


def syntax_highlight(ins):
    return H.syntax_highlight(ins, filename=".asm")


# Returns colorized instructions assembly and operands, and checkmark if branch is taken
#  Example: `✔ je     _IO_file_xsputn+341`. Inline symbol replacements made. No annotation or branch targets shown.
def one_instruction(ins: PwndbgInstruction) -> str:
    asm = "%-06s %s" % (ins.mnemonic, ins.op_str)
    if pwndbg.gdblib.config.syntax_highlight:
        asm = syntax_highlight(asm)

    # Highlight the current line if enabled
    if pwndbg.gdblib.config.highlight_pc and ins.address == pwndbg.gdblib.regs.pc:
        asm = C.highlight(asm)

    if ins.can_change_instruction_pointer:
        sym = ins.target_string

        # If it's a constant expression (immediate value), color it directly in the asm.
        # TODO: Remove this, is false most of the time
        if ins.target_const:
            asm = asm.replace(hex(ins.target), sym)

    is_call_or_jump = ins.groups_set & capstone_branch_groups

    # Style the instruction mnemonic if it's a call/jump instruction.
    if is_call_or_jump:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    # If we know the conditional is taken, mark it as taken.
    if ins.condition is True or ins.is_conditional_jump_taken:
        asm = on("✔ ") + asm
    else:
        asm = "  " + asm

    return asm


# To making the padding visually nicer, so don't need to track eye back and forth long distances to view annotations.
# but at the same time make padding non-jagged, the following padding scheme is used for annotations:
# Instruction uses the same amount left-adjusting length as the instruction before it (to keep them on the same level),
# as long as there are at least a couple characters of whitespace.
# Otherwise, it makes it so there are 'disasm_annotations_whitespace_padding' (a config value) characters of whitespace
# In order for the whitespace to being smaller again, there needs to be two instructions in a row that have too much whitespace
def instructions_and_padding(instructions: list[PwndbgInstruction]) -> list[str]:
    assembly = [one_instruction(i) for i in instructions]

    result: list[str] = []

    DEFAULT_WHITESPACE = int(pwndbg.gdblib.config.disasm_annotations_whitespace_padding)
    MIN_SPACING = 5
    # The maximum number of spaces to allow between instruction and annotation. Chosen based on stepping through x86 binaries and this constant giving a good balance.
    WHITESPACE_LIMIT = max(20, DEFAULT_WHITESPACE + 5)

    cur_padding_len = None

    # Stores intermediate padding results so we can do a final pass to clean up edges and jagged parts
    # None if padding doesn't apply to the instruction
    paddings = []

    for i, (ins, asm) in enumerate(zip(instructions, assembly)):
        if ins.can_change_instruction_pointer:
            sym = ins.target_string

            asm = f"{ljust_colored(asm, 36)} <{sym}>"

            paddings.append(None)
        else:
            raw_len = len(strip(asm))

            # Padding the string for a nicer output
            if cur_padding_len is None:
                cur_padding_len = raw_len + DEFAULT_WHITESPACE

            if cur_padding_len - raw_len < MIN_SPACING:
                # Annotations are getting too close to the disasm, push them to the right again
                cur_padding_len = raw_len + DEFAULT_WHITESPACE
            else:
                # This path deals with situations like below:
                #   mov    dword ptr [something_super_long], eax            Annotation
                #   pop rax        Annotation_all_the_way_here
                #   mov    rax, qword ptr [more_super_long]                 Annotation
                #
                # It prevents jagged annotations like shown above. Instead, it puts all annotations on the same column
                # Checks the length of the following instruction to determine where to put the annotation

                # Make sure there is an instruction after this one, and it's not a branch. If branch, just maintain current indentation.
                if i < len(instructions) - 1 and not instructions[i + 1].can_change_instruction_pointer:
                    next_len = len(strip(assembly[i + 1]))

                    # If next instructions also has too much white space, put annotations closer to left again
                    if (
                        cur_padding_len - raw_len > WHITESPACE_LIMIT
                        and next_len is not None
                        and cur_padding_len - next_len > WHITESPACE_LIMIT
                    ):
                        cur_padding_len = max(next_len, raw_len) + DEFAULT_WHITESPACE

            if ins.annotation:
                if ins.annotation_padding is not None:
                    cur_padding_len = ins.annotation_padding
                else:
                    ins.annotation_padding = cur_padding_len

            paddings.append(cur_padding_len)

        result.append(asm)

    final_result = []

    # Final pass to be used to make final alignment of blocks cleaner (get rid of an jagged/spiky bits)
    # For example, when only one instruction in a large club has small spacing but should just be aligned with the rest
    for i, (ins, asm, padding) in enumerate(zip(instructions, result, paddings)):
        if ins.annotation:
            asm = f"{ljust_colored(asm, padding)}{ins.annotation}"

        final_result.append(asm)

    return final_result
