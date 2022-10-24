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

capstone_branch_groups = set((capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP))

c = ColorConfig(
    "disasm",
    [
        ColorParamSpec("branch", "bold", "color for disasm (branch/call instruction)"),
    ],
)


def syntax_highlight(ins):
    return H.syntax_highlight(ins, filename=".asm")


def instruction(ins):
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
        target = M.get(ins.target)
        const = ins.target_const
        hextarget = hex(ins.target)
        hexlen = len(hextarget)

        # If it's a constant expression, color it directly in the asm.
        if const:
            asm = "%s <%s>" % (ljust_colored(asm, 36), target)
            asm = asm.replace(hex(ins.target), sym or target)

        # It's not a constant expression, but we've calculated the target
        # address by emulation or other means (for example showing ret instruction target)
        elif sym:
            asm = "%s <%s; %s>" % (ljust_colored(asm, 36), target, sym)

        # We were able to calculate the target, but there is no symbol
        # name for it.
        else:
            asm += "<%s>" % (target)

    # not a branch
    elif ins.symbol:
        if is_branch and not ins.target:
            asm = "%s <%s>" % (asm, ins.symbol)

            # XXX: not sure when this ever happens
            asm += "<-- file a pwndbg bug for this"
        else:
            inlined_sym = asm.replace(hex(ins.symbol_addr), ins.symbol)

            # display symbol as mem text if no inline replacement was made
            mem_text = ins.symbol if inlined_sym == asm else None
            asm = "%s <%s>" % (ljust_colored(inlined_sym, 36), M.get(ins.symbol_addr, mem_text))

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
