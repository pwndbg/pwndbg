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
from pwndbg.color.message import on
from pwndbg.disasm.instruction import PwndbgInstruction

capstone_branch_groups = {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP}

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)


def syntax_highlight(ins):
    return H.syntax_highlight(ins, filename=".asm")


def instruction(ins: PwndbgInstruction) -> str:
    asm = "%-06s %s" % (ins.mnemonic, ins.op_str)
    if pwndbg.gdblib.config.syntax_highlight:
        asm = syntax_highlight(asm)
    is_branch = set(ins.groups) & capstone_branch_groups

    # Highlight the current line if enabled
    if pwndbg.gdblib.config.highlight_pc and ins.address == pwndbg.gdblib.regs.pc:
        asm = C.highlight(asm)

    # tl;dr is a branch?
    if ins.target not in (None, ins.address + ins.size):
        sym = pwndbg.gdblib.symbol.get(ins.target) or None
        if sym:
            sym = M.get(ins.target, sym)
            
        target = M.get(ins.target)
        const = ins.target_const

        # If it's a constant expression, color it directly in the asm.
        # Replace address with symbol if possible
        # Padding for branches is +2 of annotation so they stick out a little and are easier to see
        if const:
            asm = asm.replace(hex(ins.target), sym or target)
            asm = f"{ljust_colored(asm, 38)} <{sym or target}>"

        # It's not a constant expression, but we've calculated the target
        # address by emulation or other means (for example showing ret instruction target)
        # and we have a symbol
        elif sym:
            asm = f"{ljust_colored(asm, 38)} <{target}; {sym}>"

        # We were able to calculate the target, but there is no symbol
        # name for it.
        else:
            asm += f"<{(target)}>"

    # Not a branch - print annotations in this case
    else:
        if is_branch and not ins.target:
            asm = f"{asm} <{ins.symbol}>"

            # XXX: not sure when this ever happens
            asm += "<-- file a pwndbg bug for this"
        else:

            # If enhancement found one important symbol, and if it's a literal, try to replace it with symbol
            if ins.symbol:
                asm = asm.replace(hex(ins.symbol_addr), ins.symbol)

            if ins.annotation:
                asm = f"{ljust_colored(asm, 36)} {ins.annotation}"
            
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
