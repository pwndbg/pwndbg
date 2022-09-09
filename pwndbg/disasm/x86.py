from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

pc = X86_REG_RSP


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def regs(self, instruction, reg):
        if reg == X86_REG_RIP:
            return instruction.address + instruction.size
        elif instruction.address == pwndbg.gdblib.regs.pc:
            name = instruction.reg_name(reg)
            return pwndbg.gdblib.regs[name]
        else:
            return None

    def memory(self, instruction, op):
        current = instruction.address == pwndbg.gdblib.regs.pc

        # The only register we can reason about if it's *not* the current
        # instruction is $rip.  For example:
        # lea rdi, [rip - 0x1f6]

        target = 0

        # There doesn't appear to be a good way to read from segmented
        # addresses within GDB.
        if op.mem.segment != 0:
            return None

        if op.mem.base != 0:
            base = self.regs(instruction, op.mem.base)
            if base is None:
                return None
            target += base

        if op.mem.disp != 0:
            target += op.value.mem.disp

        if op.mem.index != 0:
            scale = op.mem.scale
            index = self.regs(instruction, op.mem.index)
            if index is None:
                return None

            target += scale * index

        return target

    def memory_sz(self, instruction, op):
        arith = False
        segment = op.mem.segment
        disp = op.value.mem.disp
        base = op.value.mem.base
        index = op.value.mem.index
        scale = op.value.mem.scale
        sz = ""

        if segment != 0:
            sz += "%s:" % instruction.reg_name(segment)

        if base != 0:
            sz += instruction.reg_name(base)
            arith = True

        if index != 0:
            if arith:
                sz += " + "

            index = pwndbg.gdblib.regs[instruction.reg_name(index)]
            sz += "%s*%#x" % (index, scale)
            arith = True

        if op.mem.disp != 0:
            if arith and op.mem.disp < 0:
                sz += " - "
            elif arith and op.mem.disp >= 0:
                sz += " + "
            sz += "%#x" % abs(op.mem.disp)

        sz = "[%s]" % sz
        return sz

    def register(self, instruction, operand):
        if operand.value.reg != X86_REG_RIP:
            return super(DisassemblyAssistant, self).register(instruction, operand)

        return instruction.address + instruction.size

    def next(self, instruction, call=False):
        # Only enhance 'ret'
        if X86_INS_RET != instruction.id or len(instruction.operands) > 1:
            return super(DisassemblyAssistant, self).next(instruction, call)

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

        cf = efl & (1 << 0)
        pf = efl & (1 << 2)
        af = efl & (1 << 4)
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
