import capstone
from capstone import *

groups = {v:k for k,v in globals().items() if k.startswith('CS_GRP_')}
ops    = {v:k for k,v in globals().items() if k.startswith('CS_OP_')}
access = {v:k for k,v in globals().items() if k.startswith('CS_AC_')}

for value1, name1 in access.items():
    for value2, name2 in access.items():
        access.setdefault(value1 | value2, '%s | %s' % (name1, name2))


class DisassemblyAssistant(object):
    # Registry of all instances, {architecture: instance}
    assistants = {}

    def __init__(self):
        self.op_handlers = {
            CS_OP_IMM: self.immediate,
            CS_OP_REG: self.register,
            CS_OP_MEM: self.memory
        }

        self.op_names = {
            CS_OP_IMM: self.immediate_sz,
            CS_OP_REG: self.register_sz,
            CS_OP_MEM: self.memory_sz
        }

    @classmethod
    def get(cls, architecture):
        return cls.assistants(architecture)

    def operands(self, instruction):
        current = (instruction.address == pwndbg.regs.pc)

        rv = collections.OrderedDict()

        for i, op in enumerate(instruction.operands):
            T = op.type

            if not current or T not in op_handlers:
                rv['op%i' % i] = None
                continue

            result = self.op_handlers[T](instruction, op)

            if result is not None:
                rv[self.op_names[T]] = result

        return rv

    def immediate(self, instruction, operand):
        return operand.value.imm

    def immediate_sz(self, instruction, operand):
        return "%#x" % self.immediate(instruction, operand)

    def register(self, instruction, operand):
        # Don't care about registers which are only overwritten
        if operand.access & CS_AC_READ == 0:
            return None

        reg  = operand.value.reg
        name = instruction.reg_name(reg)

        return pwndbg.regsisters[name]

    def register_sz(self, instruction, operand):
        reg  = operand.value.reg
        return instruction.reg_name(reg).lower()

    def memory(self, instruction, operand):
        return None

    def memory_sz(self, instruction, operand):
        raise NotImplementedError

    def dump(self, instruction):
        ins = instruction
        rv  = []
        rv.append('%s %s' % (ins.mnemonic,ins.op_str))

        for i, group in enumerate(ins.groups):
            rv.append('   groups[%i]   = %s' % (i, groups[group]))

        ops = self.operands(instruction)

        for i, ((name, value), op) in enumerate(zip(ops.items(), ins.operands)):
            rv.append('   operands[%i] = %s' % (i, ops[op.type]))
            rv.append('       access   = %s' % (get_access(op.access)))

            if None not in (name, value):
                rv.append('       %s   = %#x' % (name, value))

        return '\n'.join(rv)
