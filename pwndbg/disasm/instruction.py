from __future__ import annotations

import typing

import gdb
from capstone import *  # noqa: F403


# The member variables of this class are used for provide context to an instructions execution.
#   See 'pwndbg.color.disasm.instruction()' for usage in disasm view output
# Other fields, such as "next", are used to determine breakpoints for Pwndbg commands like "nextcall"
class PwndbgInstruction:
    def __init__(self, cs_insn: CsInsn | None) -> None:
        # The underlying Capstone instruction, if present
        # Ideally, only the enhancement code will access the 'cs_insn' property,
        self.cs_insn: CsInsn = cs_insn

        # None if Capstone don't support the arch being disassembled
        # See "make_simple_instruction" function
        if cs_insn is None:
            return

        self.address: int = cs_insn.address

        # Length of the instruction
        self.size: int = cs_insn.size

        # Ex: 'MOV'
        self.mnemonic: str = cs_insn.mnemonic

        # Ex: 'RAX, RDX'
        self.op_str: str = cs_insn.op_str

        # Instruction groups that we belong to
        # Integer constants defined in capstone.__init__.py
        #   CS_GRP_INVALID | CS_GRP_JUMP | CS_GRP_CALL | CS_GRP_RET | CS_GRP_INT | CS_GRP_IRET | CS_GRP_PRIVILEGE | CS_GRP_BRANCH_RELATIVE
        self.groups: list[int] = cs_insn.groups

        # The underlying Capstone ID for the instruction
        # Examples: X86_INS_JMP, X86_INS_CALL, RISCV_INS_C_JAL
        self.id: int = cs_insn.id

        # For ease, for x86 we will assume Intel syntax (destination operand first).
        # However, Capstone will disassemble using the `set disassembly-flavor` preference,
        # and the order of operands are read left to right into the .operands array. So we flip operand order if AT&T
        if self.cs_insn._cs.syntax == CS_OPT_SYNTAX_ATT:
            self.cs_insn.operands.reverse()

        self.operands: list[EnhancedOperand] = [EnhancedOperand(op) for op in self.cs_insn.operands]

        # ***********
        # The following member variables are set during instruction enhancement
        # in pwndbg.disasm.arch.py
        # ***********

        # The address of the next instruction that is called after this, which is
        # typically self.address + self.size (the next instruction in memory).
        # If the instruction is "RET" or some sort of jump instruction (JMP, JNE)
        # and if the jump is taken - unconditionally, or it's conditional and we know its taken - then
        # we set the value to the jump target
        # Not used for "call" instructions, to indicate we will eventually return to this address
        self.next: int = self.address + self.size

        # This is the same as next, expect it includes the "call" instruction, in which case it
        # will be set to the target of the call.
        # Otherwise, it is the same as "next". This means this is target of instructions that change the PC
        self.target: int = None

        # Whether the target is a constant expression
        self.target_const: bool | None = None

        # Used for displaying jump targets
        self.symbol: str | None = None

        # Only set if symbol is set
        self.symbol_addr: int = None

        # Does the condition that the instruction checks for pass?
        # Relevent for instructions that conditionally take an action, based on a flag
        # For example, "JNE" jumps if Zero Flag is 0, else it does nothing. "CMOVA" conditionally performs a move depending on a flag.
        # See 'condition' function in pwndbg.disasm.x86 for other instructions
        # Value is either None, False, or True
        # If the instruction is always executed unconditionally (most instructions), this is set to None
        # If the instruction is executed conditional, and we can determine it indeed execute, the value is True
        # Else, False.
        self.condition: bool | None = None

        # The string is set in the "DisassemblyAssistant.enchance" function.
        # It is used in the disasm print view to add context to the instruction, mostly operand value
        # This string is not used for all cases - if the instruction is a call or a jump, the 'target'
        # variables is used instead. See 'pwndbg.color.disasm.instruction()' for specific usage
        self.annotation: str | None = None

    @property
    def bytes(self) -> bytearray:
        """
        Raw machine instruction bytes
        """
        return self.cs_insn.bytes

    def op_find(self, op_type: int, position: int) -> EnhancedOperand:
        """Get the operand at position @position of all operands having the same type @op_type"""
        cs_op = self.cs_insn.op_find(op_type, position)
        # Find the matching EnhancedOperand
        for x in self.operands:
            if x.cs_op == cs_op:
                return x
        return None

    def op_count(self, op_type: int) -> int:
        """Return number of operands having same operand Capstone type 'op_type'"""
        return self.cs_insn.op_count(op_type)


    def __repr__(self) -> str:

        return f"""
        {self.mnemonic} {self.op_str} at {self.address} (size={self.size})
            Next: {self.next}
            Target: {self.target}, const={self.target_const}
            Symbol: {self.symbol} {self.symbol_addr}
            Condition: {self.condition}
            ID: {self.id}
            Groups: {self.groups}
            Annotation: {self.annotation}
            Operands: {", ".join([repr(op) for op in self.operands])}
        """

class EnhancedOperand:
    def __init__(self, cs_op):
        # Underlying Capstone operand
        # Takes a different value depending on the architecture
        # x86 = capstone.x86.X86Op, arm = capstone.arm.ArmOp, mips = capstone.mips.MipsOp
        self.cs_op: typing.Any = cs_op

        # ***********
        # The following member variables are set during instruction enhancement
        # in pwndbg.disasm.arch.py
        # ***********

        # The value of the operand before the instruction executes.
        # This is set only if the operand value can be reasoned about.
        self.before_value: int | None = None

        # The value of the operand after the instruction executes.
        # Only set when using Emulation.
        self.after_value: int | None = None

        # String representing the operand
        # Ex: "RAX"
        self.str: str | None = ""

        # Resolved symbol name for this operand, if .before_value is set, else None.
        self.symbol: str | None = None

    @property
    def type(self) -> int:
        """
        CS_OP_REG | CS_OP_MEM | CS_OP_IMM | CS_OP_INVALID | CS_OP_FP
        """
        return self.cs_op.type

    @property
    def size(self) -> int:
        """
        Operand read/write size
        Ex: dword ptr [RDX] has size = 4
        Ex: AL has size = 1
        """
        return self.cs_op.size

    @property
    def reg(self) -> int:
        """
        The underlying Capstone ID for the register
        """
        return self.cs_op.reg

    @property
    def imm(self) -> int:
        """
        The immediate value of the operand (if applicable)
        """
        return self.cs_op.imm

    @property
    def mem(self) -> typing.Any:
        """
        Return the underlying Capstone mem object (if applicable)
        """
        return self.cs_op.value.mem
    
    def __repr__(self) -> str:
        return f"{self.str}: {self.before_value} -> {self.after_value}"


# Instantiate a PwndbgInstruction for an architecture that Capstone/pwndbg doesn't support
# (as defined in the CapstoneArch structure at the top of this file)
def make_simple_instruction(address: int) -> PwndbgInstruction:
    ins = gdb.newest_frame().architecture().disassemble(address)[0]
    asm = ins["asm"].split(maxsplit=1)

    pwn_ins = PwndbgInstruction(None)
    pwn_ins.address = address
    pwn_ins.size = ins["length"]

    pwn_ins.mnemonic = asm[0].strip()
    pwn_ins.op_str = asm[1].strip() if len(asm) > 1 else ""

    pwn_ins.next = address + pwn_ins.size
    pwn_ins.target = pwn_ins.next

    pwn_ins.groups = []
    pwn_ins.symbol = None

    # This was false in previous code for some reason
    pwn_ins.condition = False

    pwn_ins.annotation = None

    pwn_ins.operands = []

    return pwn_ins
