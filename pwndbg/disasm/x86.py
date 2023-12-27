from __future__ import annotations

from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403

from pwndbg.emu.emulator import Emulator 
import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.chain

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

pc = X86_REG_RSP

# TODO: Make this more complete
MOV_INSTRUCTIONS = {
    X86_INS_MOV,
    X86_INS_MOVABS,
    X86_INS_MOVZX,

    X86_INS_MOVD,
    X86_INS_MOVQ,
}

class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):

    # Overload
    def enhance_operands(self, instruction: CsInsn, emu: Emulator = None) -> None:
        super().enhance_operands(instruction, emu)

        # TODO: Assume Intel syntax, flip operand order if AT&T

        # MOV instructions
        if instruction.id in MOV_INSTRUCTIONS:
            if len(instruction.operands) == 2:
                left, right = instruction.operands
                if left.int is not None and right.int is not None:
                    if left.type == CS_OP_MEM: # right.type must then be either CS_OP_REG or CS_OP_IMM. Cannot MOV mem to mem
                        instruction.info_string = f"[{M.get(left.int)}] => {pwndbg.chain.format(right.int)}"
                    elif left.type == CS_OP_REG and right.type in (CS_OP_REG, CS_OP_IMM):
                        regname = C.register_changed(C.register(left.str.upper()))
                        instruction.info_string = f"{regname} => {pwndbg.chain.format(right.int)}"
                    elif left.type == CS_OP_REG and right.type == CS_OP_MEM:
                        regname = C.register_changed(C.register(left.str.upper()))
                        instruction.info_string = f"{regname}=[{M.get(right.int)}] => {pwndbg.chain.format(pwndbg.chain.get(right.int, include_start=False))}"
        elif instruction.id == X86_INS_LEA:
            # Example: lea    rdx, [rax*8]
            left, right = instruction.operands
            if left.int is not None and right.int is not None:
                regname = C.register_changed(C.register(left.str.upper()))
                instruction.info_string = f"{regname} => {M.get(right.int)}"

    # Read value at register
    def parse_register(self, instruction: CsInsn, operand, emu: Emulator):
        if operand.value.reg == X86_REG_RIP:
            return instruction.address + instruction.size
        else:
            return super().parse_register(instruction, operand, emu)
       

    # def read_register(self, instruction: CsInsn, reg):
    #     if reg == X86_REG_RIP:
    #         return instruction.address + instruction.size
    #     elif instruction.address == pwndbg.gdblib.regs.pc:
    #         name = instruction.reg_name(reg)
    #         return pwndbg.gdblib.regs[name]
    #     else:
    #         return None


    # Get memory address (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55)
    def parse_memory(self, instruction: CsInsn, op, emu: Emulator = None):
        
        print(f"x86 attempting to read memory value {self.memory_string(instruction, op)}")

        # If the current instruction is the program counter, we can reason about all addresses
        instruction_is_at_pc = instruction.address == pwndbg.gdblib.regs.pc

        # The only register we can reason about if it's *not* the current
        # instruction is $rip.  For example:
        # lea rdi, [rip - 0x1f6]

        target = 0

        # There doesn't appear to be a good way to read from segmented
        # addresses within GDB.
        if op.mem.segment != 0:
            return None

        if op.mem.base != 0:
            base = super().read_register(instruction, instruction.reg_name(op.mem.base), emu)
            # read_register(instruction, op.mem.base)
            if base is None:
                return None
            target += base

        if op.mem.disp != 0:
            target += op.value.mem.disp

        if op.mem.index != 0:
            scale = op.mem.scale
            index = self.read_register(instruction, instruction.reg_name(op.mem.index), emu)
            # index = self.read_register(instruction, op.mem.index)
            if index is None:
                return None

            target += scale * index

        return target

    def memory_string(self, instruction, op):
        arith = False
        segment = op.mem.segment
        # disp = op.value.mem.disp
        base = op.value.mem.base
        index = op.value.mem.index
        scale = op.value.mem.scale
        sz = ""

        if segment != 0:
            sz += f"{instruction.reg_name(segment)}:"

        if base != 0:
            sz += instruction.reg_name(base)
            arith = True

        if index != 0:
            if arith:
                sz += " + "

            index = pwndbg.gdblib.regs[instruction.reg_name(index)]
            sz += f"{index}*{scale:#x}"
            arith = True

        if op.mem.disp != 0:
            if arith and op.mem.disp < 0:
                sz += " - "
            elif arith and op.mem.disp >= 0:
                sz += " + "
            sz += "%#x" % abs(op.mem.disp)

        sz = f"[{sz}]"
        return sz


    def next(self, instruction, call=False):
        # Only enhance 'ret'
        if X86_INS_RET != instruction.id or len(instruction.operands) > 1:
            return super().next(instruction, call)

        # Stop disassembling at RET if we won't know where it goes to
        if instruction.address != pwndbg.gdblib.regs.pc:
            return None

        # Otherwise, resolve the return on the stack
        pop = 0
        if instruction.operands:
            pop = instruction.operands[0].int

        address = (pwndbg.gdblib.regs.sp) + (pwndbg.gdblib.arch.ptrsize * pop)

        if pwndbg.gdblib.memory.peek(address):
            return int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, address))

    def condition(self, instruction):
        # JMP is unconditional
        if instruction.id in (X86_INS_JMP, X86_INS_RET, X86_INS_CALL):
            return None

        # We can't reason about anything except the current instruction
        if instruction.address != pwndbg.gdblib.regs.pc:
            return False

        efl = pwndbg.gdblib.regs.eflags
        if efl is None:
            return False

        cf = efl & (1 << 0)
        pf = efl & (1 << 2)
        # af = efl & (1 << 4)
        zf = efl & (1 << 6)
        sf = efl & (1 << 7)
        of = efl & (1 << 11)

        return {
            X86_INS_CMOVA: not (cf or zf),
            X86_INS_CMOVAE: not cf,
            X86_INS_CMOVB: cf,
            X86_INS_CMOVBE: cf or zf,
            X86_INS_CMOVE: zf,
            X86_INS_CMOVG: not zf and (sf == of),
            X86_INS_CMOVGE: sf == of,
            X86_INS_CMOVL: sf != of,
            X86_INS_CMOVLE: zf or (sf != of),
            X86_INS_CMOVNE: not zf,
            X86_INS_CMOVNO: not of,
            X86_INS_CMOVNP: not pf,
            X86_INS_CMOVNS: not sf,
            X86_INS_CMOVO: of,
            X86_INS_CMOVP: pf,
            X86_INS_CMOVS: sf,
            X86_INS_JA: not (cf or zf),
            X86_INS_JAE: not cf,
            X86_INS_JB: cf,
            X86_INS_JBE: cf or zf,
            X86_INS_JE: zf,
            X86_INS_JG: not zf and (sf == of),
            X86_INS_JGE: sf == of,
            X86_INS_JL: sf != of,
            X86_INS_JLE: zf or (sf != of),
            X86_INS_JNE: not zf,
            X86_INS_JNO: not of,
            X86_INS_JNP: not pf,
            X86_INS_JNS: not sf,
            X86_INS_JO: of,
            X86_INS_JP: pf,
            X86_INS_JS: sf,
        }.get(instruction.id, None)


assistant = DisassemblyAssistant("i386")
assistant = DisassemblyAssistant("x86-64")
