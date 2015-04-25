import pwndbg.arch
import pwndbg.memory
import pwndbg.regs

from capstone import *
from capstone.x86 import *

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

class TargetResolver(object):
    groups = {v:k for k,v in globals().items() if k.startswith('X86_GRP_')}
    ops    = {v:k for k,v in globals().items() if k.startswith('X86_OP_')}
    regs   = {v:k for k,v in globals().items() if k.startswith('X86_REG_')}

    def __init__(self):
        self.classes = {
            X86_GRP_CALL: self.call_or_jump,
            X86_GRP_JUMP: self.call_or_jump,
            X86_GRP_RET: self.ret
        }

    def resolve(self, address):
        code = bytes(pwndbg.memory.read(address, 16))

        md.mode = CS_MODE_32 if pwndbg.arch.ptrsize == 4 else CS_MODE_64

        instruction = next(md.disasm(code, address, 1))

        for group in instruction.groups:
            function = self.classes.get(group, None)
            print(self.groups[group])
            if function:
                return function(instruction)

    def get_operand_target(self, op):
        # EB/E8/E9 or similar "call $+offset"
        # Capstone handles the instruction + instruction size.
        if op.type == X86_OP_IMM:
            return op.value.imm

        # jmp/call REG
        if op.type == X86_OP_REG:
            regname = instruction.reg_name(op.value.reg)
            return pwndbg.regs[regname]

        # base + disp + scale * offset
        assert op.type == X86_OP_MEM, "Invalid operand type %i" % op.type

        target = 0

        if op.mem.base != 0:
            regname = instruction.reg_name(op.value.reg)
            target += pwndbg.regs[regname]

        if op.mem.disp != 0:
            target += op.value.mem.disp

        if op.mem.index != 0:
            scale = op.mem.scale
            index = pwndbg.regs[instruction.reg_name(op.mem.index)]
            target += (scale * index)

        return target


    def call_or_jump(self, instruction):
        ops = instruction.operands
        assert len(ops) == 1, "Too many operands (%i)" % len(ops)

        return self.get_operand_target(ops[0])

    def ret(self, instruction):
        target = pwndbg.regs.sp

        for op in instruction.operands:
            assert op.type == X86_OP_IMM, "Unknown RET operand type"
            target += op.value.imm

        return pwndbg.memory.pvoid(target)

resolver = TargetResolver()
