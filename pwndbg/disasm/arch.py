import gdb
from capstone import *  # noqa: F403

import pwndbg.gdblib.symbol
import pwndbg.lib.memoize

debug = False

groups = {v: k for k, v in globals().items() if k.startswith("CS_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("CS_OP_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

for value1, name1 in dict(access).items():
    for value2, name2 in dict(access).items():
        # novermin
        access.setdefault(value1 | value2, "%s | %s" % (name1, name2))


class DisassemblyAssistant:
    # Registry of all instances, {architecture: instance}
    assistants = {}

    def __init__(self, architecture):
        if architecture is not None:
            self.assistants[architecture] = self

        self.op_handlers = {
            CS_OP_IMM: self.immediate,
            CS_OP_REG: self.register,
            CS_OP_MEM: self.memory,
        }

        self.op_names = {
            CS_OP_IMM: self.immediate_sz,
            CS_OP_REG: self.register_sz,
            CS_OP_MEM: self.memory_sz,
        }

    @staticmethod
    def enhance(instruction):
        enhancer = DisassemblyAssistant.assistants.get(
            pwndbg.gdblib.arch.current, generic_assistant
        )
        enhancer.enhance_operands(instruction)
        enhancer.enhance_symbol(instruction)
        enhancer.enhance_conditional(instruction)
        enhancer.enhance_next(instruction)

        if debug:
            print(enhancer.dump(instruction))

    def enhance_conditional(self, instruction):
        """
        Adds a ``condition`` field to the instruction.

        If the instruction is always executed unconditionally, the value
        of the field is ``None``.

        If the instruction is executed conditionally, and we can be absolutely
        sure that it will be executed, the value of the field is ``True``.
        Generally, this implies that it is the next instruction to be executed.

        In all other cases, it is set to ``False``.
        """
        c = self.condition(instruction)

        if c:
            c = True
        elif c is not None:
            c = False

        instruction.condition = c

    def condition(self, instruction):
        return False

    def enhance_next(self, instruction):
        """
        Adds a ``next`` field to the instruction.

        By default, it is set to the address of the next linear
        instruction.

        If the instruction is a non-"call" branch and either:

        - Is unconditional
        - Is conditional, but is known to be taken

        And the target can be resolved, it is set to the address
        of the jump target.
        """
        next_addr = None

        if instruction.condition in (True, None):
            next_addr = self.next(instruction)

        instruction.target = None
        instruction.target_const = None
        instruction.next = None

        if next_addr is None:
            next_addr = instruction.address + instruction.size
            instruction.target = self.next(instruction, call=True)

        instruction.next = next_addr & pwndbg.gdblib.arch.ptrmask

        if instruction.target is None:
            instruction.target = instruction.next

        if instruction.operands and instruction.operands[0].int:
            instruction.target_const = True

    def next(self, instruction, call=False):
        """
        Architecture-specific hook point for enhance_next.
        """
        if CS_GRP_CALL in instruction.groups:
            if not call:
                return None

        elif CS_GRP_JUMP not in instruction.groups:
            return None

        # At this point, all operands have been resolved.
        # Assume only single-operand jumps.
        if len(instruction.operands) != 1:
            return None

        # Memory operands must be dereferenced
        op = instruction.operands[0]
        addr = op.int
        if addr:
            addr &= pwndbg.gdblib.arch.ptrmask
        if op.type == CS_OP_MEM:
            if addr is None:
                addr = self.memory(instruction, op)

            # self.memory may return none, so we need to check it here again
            if addr is not None:
                try:
                    # fails with gdb.MemoryError if the dereferenced address
                    # doesn't belong to any of process memory maps
                    addr = int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, addr))
                except gdb.MemoryError:
                    return None
        if op.type == CS_OP_REG:
            addr = self.register(instruction, op)

        # Evidently this can happen?
        if addr is None:
            return None

        return int(addr)

    def enhance_symbol(self, instruction):
        """
        Adds a ``symbol`` and ``symbol_addr`` fields to the instruction.

        If, after parsing all of the operands, there is exactly one
        value which resolved to a named symbol, it will be set to
        that value.

        In all other cases, the value is ``None``.
        """
        instruction.symbol = None
        operands = [o for o in instruction.operands if o.symbol]

        if len(operands) != 1:
            return

        o = operands[0]

        instruction.symbol = o.symbol
        instruction.symbol_addr = o.int

    def enhance_operands(self, instruction):
        """
        Enhances all of the operands in the instruction, by adding the following
        fields:

        operand.str:
            String of this operand, as it should appear in the
            disassembly.

        operand.int:
            Integer value of the operand, if it can be resolved.

        operand.symbol:
            Resolved symbol name for this operand.
        """
        for i, op in enumerate(instruction.operands):
            op.int = None
            op.symbol = None

            op.int = self.op_handlers.get(op.type, lambda *a: None)(instruction, op)
            if op.int:
                op.int &= pwndbg.gdblib.arch.ptrmask
            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

            if op.int:
                op.symbol = pwndbg.gdblib.symbol.get(op.int)

    def immediate(self, instruction, operand):
        return operand.value.imm

    def immediate_sz(self, instruction, operand):
        value = operand.int

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    def register(self, instruction, operand):
        if instruction.address != pwndbg.gdblib.regs.pc:
            return None

        # # Don't care about registers which are only overwritten
        # if operand.access & CS_AC_WRITE and not operand.access & CS_AC_READ:
        #     return None

        reg = operand.value.reg
        name = instruction.reg_name(reg)

        return pwndbg.gdblib.regs[name]

    def register_sz(self, instruction, operand):
        reg = operand.value.reg
        return instruction.reg_name(reg).lower()

    def memory(self, instruction, operand):
        return None

    def memory_sz(self, instruction, operand):
        return None  # raise NotImplementedError

    def dump(self, instruction):
        """
        Debug-only method.
        """
        ins = instruction
        rv = []
        rv.append("%s %s" % (ins.mnemonic, ins.op_str))

        for i, group in enumerate(ins.groups):
            rv.append("   groups[%i]   = %s" % (i, groups.get(group, group)))

        rv.append("           next = %#x" % (ins.next))
        rv.append("      condition = %r" % (ins.condition))

        for i, op in enumerate(ins.operands):
            rv.append("   operands[%i] = %s" % (i, ops.get(op.type, op.type)))
            rv.append("       access   = %s" % (access.get(op.access, op.access)))

            if op.int is not None:
                rv.append("            int = %#x" % (op.int))
            if op.symbol is not None:
                rv.append("            sym = %s" % (op.symbol))
            if op.str is not None:
                rv.append("            str = %s" % (op.str))

        return "\n".join(rv)


generic_assistant = DisassemblyAssistant(None)
