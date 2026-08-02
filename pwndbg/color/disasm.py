from __future__ import annotations

import contextlib

from capstone6pwndbg import CS_OP_IMM

import pwndbg.aglib
import pwndbg.aglib.nearpc
import pwndbg.color.context as ctx_color
from pwndbg.aglib.disasm.assistant import DisassemblyAssistant
from pwndbg.aglib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.color import gray
from pwndbg.color import ljust_colored
from pwndbg.color import strip
from pwndbg.color import theme
from pwndbg.color.message import off
from pwndbg.color.message import on

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)

config_branch_on = theme.add_param(
    "disasm-branch-on", "✔", "marker for branches that WILL be taken"
)
config_branch_off = theme.add_param(
    "disasm-branch-off", "✘", "marker for branches that will NOT be taken"
)


def one_instruction(ins: PwndbgInstruction, linear: bool) -> str:
    """
    Returns colorized instructions assembly and operands, and checkmark if branch is taken

    Example: `✔ je     _IO_file_xsputn+341`. Inline symbol replacements made. No annotation or branch targets shown.
    """
    asm = ins.asm_string

    # Highlight the current line if enabled
    if pwndbg.config.highlight_pc and ins.address == pwndbg.aglib.regs.pc:
        asm = ctx_color.highlight(asm)

    is_call_or_jump = ins.groups & ALL_JUMP_GROUPS

    # Style the instruction mnemonic if it's a call/jump instruction.
    if is_call_or_jump:
        asm = asm.replace(ins.mnemonic, c.branch(ins.mnemonic), 1)

    if linear:
        asm = f"  {asm}"
    # If we know the conditional is taken, mark it as taken.
    elif ins.condition == InstructionCondition.TRUE or ins.is_conditional_jump_taken:
        asm = on(f"{config_branch_on} ") + asm
    elif ins.condition == InstructionCondition.FALSE:
        asm = off(f"{config_branch_off} ") + asm
    elif ins.condition == InstructionCondition.UNDETERMINED_CONDITIONAL:
        asm = gray("? ") + asm
    else:
        asm = f"  {asm}"

    return asm


def decode_immediate_string(val: int) -> str | None:
    if val <= 0:
        return None
    byte_len = (val.bit_length() + 7) // 8
    if byte_len < 2:
        return None
    try:
        b = val.to_bytes(byte_len, "little")
        # Try UTF-8 decoding (supports Russian, Cyrillic, UTF-8 multi-byte strings)
        try:
            s = b.decode("utf-8")
            if all(c.isprintable() or c in ("\n", "\r", "\t") for c in s):
                escaped = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
                if len(escaped.strip()) > 0:
                    return f'"{escaped}"'
        except UnicodeDecodeError:
            pass

        # Fallback ASCII check
        if all(32 <= c <= 126 or c in (9, 10, 13) for c in b):
            s = (
                b.decode("ascii", errors="ignore")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t")
            )
            if len(s.strip()) > 0:
                return f'"{s}"'
    except (ValueError, TypeError, OverflowError):
        pass
    return None


def enrich_instruction_annotation(ins: PwndbgInstruction) -> None:
    comments = []

    # 1. Check operands for immediate values (e.g. 0x68732f2f6e69622f -> "/bin//sh", 0xa798fd1bcd0 -> "мяу\n")
    for op in ins.operands:
        val = None
        if hasattr(op, "type") and op.type == CS_OP_IMM:
            with contextlib.suppress(ValueError, TypeError, AttributeError):
                val = op.imm
        elif isinstance(getattr(op, "str", None), str) and (
            op.str.startswith("0x") or op.str.isdigit()
        ):
            with contextlib.suppress(ValueError, TypeError):
                val = int(op.str, 0)

        if val and val > 0xFF:
            decoded = decode_immediate_string(val)
            if decoded and decoded not in comments:
                comments.append(decoded)

    # 2. Syscall & File descriptor detection
    if ins.mnemonic in ("mov", "movabs", "movsx", "movzx"):
        operands = ins.operands
        if len(operands) >= 2:
            dst_op, src_op = operands[0], operands[1]
            dst_str = getattr(dst_op, "str", "") or ""
            src_val = None
            if hasattr(src_op, "type") and src_op.type == CS_OP_IMM:
                with contextlib.suppress(ValueError, TypeError, AttributeError):
                    src_val = src_op.imm
            elif isinstance(getattr(src_op, "str", None), str):
                with contextlib.suppress(ValueError, TypeError):
                    src_val = int(src_op.str, 0)

            if dst_str.lower() in ("rax", "eax", "x0", "w0") and src_val is not None:
                try:
                    sys_name = DisassemblyAssistant._syscall_name(src_val, pwndbg.aglib.arch.name)
                    if sys_name:
                        hint = f"sys_{sys_name}"
                        if hint not in comments:
                            comments.append(hint)
                except (ValueError, TypeError, AttributeError):
                    pass
            elif dst_str.lower() in ("rdi", "edi", "r0", "w0") and src_val is not None:
                if src_val == 0:
                    comments.append("stdin")
                elif src_val == 1:
                    comments.append("stdout")
                elif src_val == 2:
                    comments.append("stderr")

    # 3. Single byte stores (mov byte ptr [rsp], 0xXX)
    if "byte" in ins.op_str.lower():
        for op in ins.operands:
            b_val = None
            if hasattr(op, "type") and op.type == CS_OP_IMM:
                with contextlib.suppress(ValueError, TypeError, AttributeError):
                    b_val = op.imm
            elif isinstance(getattr(op, "str", None), str):
                with contextlib.suppress(ValueError, TypeError):
                    b_val = int(op.str, 0)

            if b_val is not None and 32 <= b_val <= 126:
                c_str = f"'{chr(b_val)}'"
                if c_str not in comments:
                    comments.append(c_str)

    # 4. Memory string dereferencing
    if ins.target and pwndbg.aglib.memory.is_readable_address(ins.target):
        try:
            data = pwndbg.aglib.memory.string(ins.target, max=32)
            if data and len(data) >= 2 and all(32 <= c <= 126 for c in data):
                decoded_str = data.decode("ascii", errors="ignore")
                hint = f'-> "{decoded_str}"'
                if hint not in comments:
                    comments.append(hint)
        except (ValueError, TypeError, AttributeError, MemoryError, OSError):
            pass

    if comments:
        comment_str = gray(f"; {', '.join(comments)}")
        if ins.annotation:
            if "; " not in ins.annotation:
                ins.annotation += "  " + comment_str
        else:
            ins.annotation = comment_str


MIN_SPACING = 5
WHITESPACE_LIMIT = 20


# To making the padding visually nicer, the following padding scheme is used for annotations:
# All instructions in a group will have the same amount of left-adjusting spaces, so they are aligned.
# A group is defined as a sequence of instructions surrounded by instructions that can change the instruction pointer.
def instructions_and_padding(instructions: list[PwndbgInstruction], linear: bool) -> list[str]:
    result: list[str] = []

    for ins in instructions:
        enrich_instruction_annotation(ins)

    cur_padding_len = None

    # Stores intermediate padding results so we can do a final pass to clean up edges and jagged parts
    # None if padding doesn't apply to the instruction
    paddings: list[int | None] = []

    # Used for padding. List of groups.
    # Each group is a list of index into paddings list
    groups: list[list[int]] = []

    current_group: list[int] = []

    for i, (ins, asm) in enumerate(
        zip(instructions, (one_instruction(i, linear) for i in instructions))
    ):
        if ins.has_jump_target:
            sym = ins.target_string

            asm = f"{ljust_colored(asm, 36)} <{sym}>"

            paddings.append(None)
            if current_group:
                groups.append(current_group)
                current_group = []
        else:
            if ins.syscall is not None and ins.syscall_name:
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
            # This path allows the padding to be smaller again
            # If the instruction has too much whitespace, put the annotation more to the left
            # Make sure there is an instruction after this one, and it's not a branch. Otherwise, maintain current indentation.
            elif (
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
    for ins, asm, padding in zip(instructions, result, paddings):
        # Padding being None implies a jump target - this is already baked into "asm"
        if ins.annotation and padding is not None:
            asm = f"{ljust_colored(asm, padding)}{ins.annotation}"

        final_result.append(asm)

    return final_result
