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
    is_branch = set(ins.groups) & capstone_branch_groups

    # Highlight the current line if enabled
    if pwndbg.gdblib.config.highlight_pc and ins.address == pwndbg.gdblib.regs.pc:
        asm = C.highlight(asm)

    # Is it a branch?
    if ins.target not in (None, ins.address + ins.size):
        sym = pwndbg.gdblib.symbol.get(ins.target) or None
        if sym:
            sym = M.get(ins.target, sym)

        target = M.get(ins.target)
        const = ins.target_const

        # If it's a constant expression, color it directly in the asm.
        if const:
            asm = asm.replace(hex(ins.target), sym or target)
    else:
        # If enhancement found one important symbol, and if it's a literal, try to replace it with symbol
        if ins.symbol:
            asm = asm.replace(hex(ins.symbol_addr), ins.symbol)

    # Style the instruction mnemonic if it's a branch instruction.
    if is_branch:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    # If we know the conditional is taken, mark it as taken.
    if ins.condition is None:
        asm = "  " + asm
    elif ins.condition:
        asm = on("✔ ") + asm
    else:
        asm = "  " + asm

    return asm



# To making the padding visually nicer, so don't need to track eye back and forth long distances to view annotations.
# but at the same time make padding non-jagged, the following padding scheme is used for annotations:   
# Instruction uses the same amount left-adjusting length as the instruction before it (to keep them on the same level),
# as long as there are at least 5 characters of whitespace.
# Otherwise, it makes it so there are 'disasm_annotations_whitespace_padding' (a config value) characters of whitespace
# In order for the whitespace to being less again, there needs to be two instructions in a row that have too much whitespace
def instructions_and_padding(instructions: list[PwndbgInstruction]) -> list[str]:
    assembly = [one_instruction(i) for i in instructions]

    result: list[str] = []

    DEFAULT_WHITESPACE = int(pwndbg.gdblib.config.disasm_annotations_whitespace_padding)

    cur_padding_len = None

    
    for i, (ins, asm) in enumerate(zip(instructions, assembly)):
        # If it's a branch, 
        if ins.target not in (None, ins.address + ins.size):
            sym = pwndbg.gdblib.symbol.get(ins.target) or None
            if sym:
                sym = M.get(ins.target, sym)

            target = M.get(ins.target)
            const = ins.target_const
            if const:
                asm = f"{ljust_colored(asm, 36)} <{sym or target}>"
            # It's not a constant expression, but we've calculated the target
            # address by emulation or other means (for example showing ret instruction target)
            # and we have a symbol
            elif sym:
                asm = f"{ljust_colored(asm, 36)} <{sym}>"
            # We were able to calculate the target, but there is no symbol name for it.
            else:
                asm = f"{ljust_colored(asm, 36)} <{target}>"

        else:
            # This path deals with padding the string for a nicer output
            raw_len = len(strip(asm))

            if cur_padding_len is None:
                cur_padding_len = raw_len + DEFAULT_WHITESPACE

            if cur_padding_len - raw_len < 5:
                # Annotations are getting too close to the disasm, push them to the right again
                cur_padding_len = raw_len + DEFAULT_WHITESPACE
            else:
                # This path deals with situations like below:
                #   mov    dword ptr [something_super_long], eax            Annotation
                #   pop rax        Annotation_all_the_way_here
                #   mov    rax, qword ptr [more_super_long]                 Annotation
                # It prevents jagged annotations like shown above, instead, it puts all annotations on the same column
                # Checks the length of the following instruction to determine where to put or anotation
                WHITESPACE_LIMIT=19
                next_len = len(strip(assembly[i + 1])) if i < len(instructions) - 1 else None

                # If next instructions also has too much white space, put annotations closer to left again 
                if cur_padding_len - raw_len > WHITESPACE_LIMIT and next_len is not None and cur_padding_len - next_len > WHITESPACE_LIMIT:
                    cur_padding_len = max(next_len,raw_len) + DEFAULT_WHITESPACE

            if ins.annotation:
                if ins.annotation_padding is not None:
                    cur_padding_len = ins.annotation_padding
                else:
                    ins.annotation_padding = cur_padding_len

                asm = f"{ljust_colored(asm, cur_padding_len)}{ins.annotation}"
                
                    # if cur_padding_len is None:
                    #     cur_padding_len = raw_len + DEFAULT_WHITESPACE

                    # if cur_padding_len - raw_len < 5:
                    #     # Annotations are getting too close to the disasm, push them to the right again
                    #     cur_padding_len = raw_len + DEFAULT_WHITESPACE
                    # else:
                    #     # This path deals with situations like below:
                    #     #   mov    dword ptr [something_super_long], eax            Annotation
                    #     #   pop rax        Annotation_all_the_way_here
                    #     #   mov    rax, qword ptr [more_super_long]                 Annotation
                    #     # It prevents jagged annotations like shown above, instead, it puts all annotations on the same column
                    #     # Checks the length of the following instruction to determine where to put or anotation
                    #     WHITESPACE_LIMIT=19
                    #     next_len = len(strip(assembly[i + 1])) if i < len(instructions) - 1 else None

                    #     # If next instructions also has too much white space, put annotations closer to left again 
                    #     if cur_padding_len - raw_len > WHITESPACE_LIMIT and next_len is not None and cur_padding_len - next_len > WHITESPACE_LIMIT:
                    #         cur_padding_len = max(next_len,raw_len) + DEFAULT_WHITESPACE

                    # ins.annotation_padding = cur_padding_len
                    # asm = f"{ljust_colored(asm, cur_padding_len)}{ins.annotation}"

        result.append(asm)

    return result

