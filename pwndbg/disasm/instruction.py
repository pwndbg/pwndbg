from __future__ import annotations

import typing
from enum import Enum
from typing import Dict
from typing import List
from typing import Set
from typing import TypedDict

import gdb

# Reverse lookup tables for debug printing
from capstone import CS_AC
from capstone import CS_GRP
from capstone import CS_OP
from capstone import *  # noqa: F403
from capstone.arm import ARM_INS_B
from capstone.arm import ARM_INS_BL
from capstone.arm import ARM_INS_BLX
from capstone.arm import ARM_INS_BX
from capstone.arm import ARM_INS_BXJ
from capstone.arm import ARM_INS_TBB
from capstone.arm import ARM_INS_TBH

# from capstone.arm64 import ARM64_INS_B
from capstone.arm64 import ARM64_INS_BL
from capstone.arm64 import ARM64_INS_BLR
from capstone.arm64 import ARM64_INS_BR
from capstone.mips import MIPS_INS_B
from capstone.mips import MIPS_INS_BAL
from capstone.mips import MIPS_INS_J
from capstone.mips import MIPS_INS_JAL
from capstone.mips import MIPS_INS_JALR
from capstone.mips import MIPS_INS_JR
from capstone.ppc import PPC_INS_B
from capstone.ppc import PPC_INS_BA
from capstone.ppc import PPC_INS_BL
from capstone.ppc import PPC_INS_BLA
from capstone.riscv import RISCV_INS_JAL
from capstone.riscv import RISCV_INS_JALR
from capstone.sparc import SPARC_INS_JMP
from capstone.sparc import SPARC_INS_JMPL
from capstone.x86 import X86_INS_JMP
from capstone.x86 import X86Op

# Architecture specific instructions that mutate the instruction pointer unconditionally
# The Capstone RET and CALL groups are also used to filter CALL and RET types when we check for unconditional jumps,
# so we don't need to manually specify those for each architecture
UNCONDITIONAL_JUMP_INSTRUCTIONS: Dict[int, Set[int]] = {
    CS_ARCH_X86: {X86_INS_JMP},
    CS_ARCH_MIPS: {MIPS_INS_J, MIPS_INS_JR, MIPS_INS_JAL, MIPS_INS_JALR, MIPS_INS_BAL, MIPS_INS_B},
    CS_ARCH_SPARC: {SPARC_INS_JMP, SPARC_INS_JMPL},
    CS_ARCH_ARM: {
        ARM_INS_B,
        ARM_INS_BL,
        ARM_INS_BLX,
        ARM_INS_BX,
        ARM_INS_BXJ,
        ARM_INS_TBB,
        ARM_INS_TBH,
    },
    CS_ARCH_ARM64: {ARM64_INS_BL, ARM64_INS_BLR, ARM64_INS_BR},
    CS_ARCH_RISCV: {RISCV_INS_JAL, RISCV_INS_JALR},
    CS_ARCH_PPC: {PPC_INS_B, PPC_INS_BA, PPC_INS_BL, PPC_INS_BLA},
}

# Everything that is a CALL or a RET is a unconditional jump
GENERIC_UNCONDITIONAL_JUMP_GROUPS = {CS_GRP_CALL, CS_GRP_RET}
# All branch-like instructions - jumps thats are non-call and non-ret - should have one of these two groups in Capstone
GENERIC_JUMP_GROUPS = {CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE}
# All Capstone jumps should have at least one of these groups
ALL_JUMP_GROUPS = GENERIC_JUMP_GROUPS | GENERIC_UNCONDITIONAL_JUMP_GROUPS


class InstructionCondition(Enum):
    # Conditional instruction, and action is taken
    TRUE = 1
    # Conditional instruction, but action is not taken
    FALSE = 2
    # Unconditional instructions (most instructions), or we cannot reason about the instruction
    UNDETERMINED = 3


# Only use within the instruction.__repr__ to give a nice output
CAPSTONE_ARCH_MAPPING_STRING = {
    CS_ARCH_ARM: "arm",
    CS_ARCH_ARM64: "aarch64",
    CS_ARCH_X86: "x86",
    CS_ARCH_PPC: "powerpc",
    CS_ARCH_MIPS: "mips",
    CS_ARCH_SPARC: "sparc",
    CS_ARCH_RISCV: "RISCV",
}


# This class is used to provide context to an instructions execution, used both
# in the disasm view output (see 'pwndbg.color.disasm.instruction()'), as well as for
# Pwndbg commands like "nextcall" that need to know the instructions target to set breakpoints
class PwndbgInstruction:
    def __init__(self, cs_insn: CsInsn | None) -> None:
        self.cs_insn: CsInsn = cs_insn
        """
        The underlying Capstone instruction, if present.
        Ideally, only the enhancement code will access the 'cs_insn' property
        """

        # None if Capstone don't support the arch being disassembled
        # See "make_simple_instruction" function
        if cs_insn is None:
            return

        self.address: int = cs_insn.address

        self.size: int = cs_insn.size
        """
        Length of the instruction
        """

        self.mnemonic: str = cs_insn.mnemonic
        """
        Ex: 'MOV'
        """

        self.op_str: str = cs_insn.op_str
        """
        Ex: 'RAX, RDX'
        """

        self.groups: List[int] = cs_insn.groups
        """
        Capstone instruction groups that we belong to.
        Groups that apply to all architectures: CS_GRP_INVALID | CS_GRP_JUMP | CS_GRP_CALL | CS_GRP_RET | CS_GRP_INT | CS_GRP_IRET | CS_GRP_PRIVILEGE | CS_GRP_BRANCH_RELATIVE
        """

        self.groups_set = set(self.groups)

        self.id: int = cs_insn.id
        """
        The underlying Capstone ID for the instruction
        Examples: X86_INS_JMP, X86_INS_CALL, RISCV_INS_C_JAL
        """

        # For ease, for x86 we will assume Intel syntax (destination operand first).
        # However, Capstone will disassemble using the `set disassembly-flavor` preference,
        # and the order of operands are read left to right into the .operands array. So we flip operand order if AT&T
        if self.cs_insn._cs.syntax == CS_OPT_SYNTAX_ATT:
            self.cs_insn.operands.reverse()

        self.operands: List[EnhancedOperand] = [EnhancedOperand(op) for op in self.cs_insn.operands]

        # ***********
        # The following member variables are set during instruction enhancement
        # in pwndbg.disasm.arch.py
        # ***********

        self.asm_string: str = "%-06s %s" % (self.mnemonic, self.op_str)
        """
        The full string representing the instruction - `mov    rdi, rsp` with appropriate padding.

        This is syntax highlighted during enhancement.

        This is additionally modified during enhancement for the purposes of replacing
        immediate values with their corresponding symbols
        """

        self.next: int = self.address + self.size
        """
        This is the address that the instruction pointer will be set to after using the "nexti" GDB command.
        This means it is the address of the next instruction to be executed in all cases except "call" instructions.

        Typically, it is `self.address + self.size` (the next instruction in memory)

        If it is a jump and we know it is taken, then it is the value of the jump target.

        Not set to "call" instruction targets, to indicate we will eventually (probably) return to this address
        """

        self.target: int = None
        """
        This is target of instructions that change the PC, regardless of if it's conditional or not,
        and whether or not we take the jump. This includes "call" and all other instructions that set the PC

        If the instruction is not one that changes the PC, target is set to "next"
        """

        self.target_string: str | None = None
        """
        String representation of the target address.

        Colorized symbol if a symbol exists at address, else colorized address
        """

        self.target_const: bool | None = None
        """
        Whether the target is a constant expression
        """

        self.condition: InstructionCondition = InstructionCondition.UNDETERMINED
        """
        Does the condition that the instruction checks for pass?

        For example, "JNE" jumps if Zero Flag is 0, else it does nothing. "CMOVA" conditionally performs a move depending on a flag.
        See 'condition' function in pwndbg.disasm.x86 for example on setting this.

        UNDETERMINED if we cannot reason about the condition, or if the instruction always executes unconditionally (most instructions).

        TRUE if the instruction has a conditional action, and we determine it is taken.

        FALSE if the instruction has a conditional action, and we know it is not taken.
        """

        self.annotation: str | None = None
        """
        The string is set in the "DisassemblyAssistant.enhance" function.
        It is used in the disasm print view to add context to the instruction, mostly operand value.
        This string is not used for all cases - if the instruction is a call or a jump, the 'target'.
        variables is used instead. See 'pwndbg.color.disasm.instruction()' for specific usage.
        """

        self.annotation_padding: int | None = None
        """
        The left adjustment padding that was used to previously print this.
        We retain it so the output is consistent between prints
        """

        self.emulated: bool = False
        """
        If the enhancement successfully used emulation for this instruction
        """

    @property
    def can_change_instruction_pointer(self) -> bool:
        """
        True if we have determined that this instruction can explicitly change the program counter.
        """
        # The second check ensures that if the target address is itself, it's a jump (infinite loop) and not something like `rep movsb` which repeats the same instruction.
        # Because capstone doesn't catch ALL cases of an instruction changing the PC, we don't have the ALL_JUMP_GROUPS in the first part of this check.
        return self.target not in (None, self.address + self.size) and (
            self.target != self.address or bool(self.groups_set & ALL_JUMP_GROUPS)
        )

    @property
    def is_conditional_jump(self) -> bool:
        """
        True if this instruction can change the program counter conditionally.

        This is used, in part, to determine if the instruction deserve a "checkmark" in the disasm view
        """
        return (
            bool(self.groups_set & GENERIC_JUMP_GROUPS)
            and self.id not in UNCONDITIONAL_JUMP_INSTRUCTIONS[self.cs_insn._cs.arch]
        )

    @property
    def is_unconditional_jump(self) -> bool:
        """
        True if we know the instruction can change the program counter, and does so unconditionally.

        This includes things like RET, CALL, and JMP (in x86).

        This property is used in enhancement to determine certain codepaths when resolving .next for this instruction.
        """
        return (
            bool(self.groups_set & GENERIC_UNCONDITIONAL_JUMP_GROUPS)
            or self.id in UNCONDITIONAL_JUMP_INSTRUCTIONS[self.cs_insn._cs.arch]
        )

    @property
    def is_conditional_jump_taken(self) -> bool:
        """
        True if this is a conditional jump, and we predicted that we will take the jump
        """
        # True if:
        # - We manually determined in .condition that we take the jump
        # - Or that emulation determined the .next to go somewhere and we didn't explicitely set .condition to False.
        #   Emulation can be incorrect, so we check the conditional for false to ensure we didn't manually override the emulator's decision
        return self.is_conditional_jump and (
            self.condition == InstructionCondition.TRUE
            or (
                (self.next not in (None, self.address + self.size))
                and self.condition != InstructionCondition.FALSE
            )
        )

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

    # For debugging
    def __repr__(self) -> str:
        operands_str = " ".join([repr(op) for op in self.operands])

        return f"""{self.mnemonic} {self.op_str} at {self.address:#x} (size={self.size}) (arch: {CAPSTONE_ARCH_MAPPING_STRING.get(self.cs_insn._cs.arch,None)})
        ID: {self.id}, {self.cs_insn.insn_name()}
        Raw asm: {'%-06s %s' % (self.mnemonic, self.op_str)}
        New asm: {self.asm_string}
        Next: {self.next:#x}
        Target: {hex(self.target) if self.target is not None else None}, Target string={self.target_string or ""}, const={self.target_const}
        Condition: {self.condition.name}
        Groups: {[CS_GRP.get(group, group) for group in self.groups]}
        Annotation: {self.annotation}
        Operands: [{operands_str}]
        Conditional jump: {self.is_conditional_jump}. Taken: {self.is_conditional_jump_taken}
        Unconditional jump: {self.is_unconditional_jump}
        Can change PC: {self.can_change_instruction_pointer}"""


class EnhancedOperand:
    def __init__(self, cs_op):
        self.cs_op: typing.Any = cs_op
        """
        Underlying Capstone operand. Takes on a different value depending on the architecture.

        x86 = capstone.x86.X86Op, arm = capstone.arm.ArmOp, mips = capstone.mips.MipsOp
        """

        # ***********
        # The following member variables are set during instruction enhancement
        # in pwndbg.disasm.arch.py
        # ***********

        self.before_value: int | None = None
        """
        The value of the operand before the instruction executes.
        This is set only if the operand value can be reasoned about.
        """

        self.after_value: int | None = None
        """
        The value of the operand after the instruction executes.
        Only set when using emulation.
        """

        self.before_value_resolved: int | None = None
        """
        The 'resolved' value of the operand that is actually used in the instruction logic, before the instruction executes.
        This is the same as before_value if it's not a memory operand, in which cases it's the dereferenced value.

        Helpful for cases like  `cmp    byte ptr [rip + 0x166669], 0`, where first operand could be
        a register or a memory value to dereference, and we want the actual value used.
        """

        self.after_value_resolved: int | None = None
        """
        The 'resolved' value of the operand after the instruction executes.
        """

        self.str: str | None = ""
        """
        String representing the operand

        Ex: "RAX", or "[0x7fffffffd9e8]". None if value cannot be determined.
        """

        self.symbol: str | None = None
        """
        Colorized symbol name for this operand, if .before_value is set and symbol exists, else None.
        """

    @property
    def type(self) -> int:
        """
        CS_OP_REG | CS_OP_MEM | CS_OP_IMM | CS_OP_INVALID | CS_OP_FP
        """
        return self.cs_op.type

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

    # For debugging
    def __repr__(self) -> str:
        info = (
            f"'{self.str}': Symbol: {self.symbol}, "
            f"Before: {hex(self.before_value) if self.before_value is not None else None}, "
            f"After: {hex(self.after_value) if self.after_value is not None else None}, "
            f"type={CS_OP.get(self.type, self.type)}"
        )

        if isinstance(self.cs_op, X86Op):
            info += (
                f", size={self.cs_op.size}, "
                f"access={CS_AC.get(self.cs_op.access, self.cs_op.access)}]"
            )

        return f"[{info}]"


# GDB does not expose a type for this
# Type defined here: https://sourceware.org/gdb/current/onlinedocs/gdb.html/Architectures-In-Python.html#Architectures-In-Python
class GDBDisassembledInstructionType(TypedDict):
    addr: int
    asm: str
    length: int


def make_simple_instruction(address: int) -> PwndbgInstruction:
    """
    Instantiate a PwndbgInstruction for an architecture that Capstone/pwndbg doesn't support (as defined in the CapstoneArch structure)
    """
    ins: GDBDisassembledInstructionType = gdb.newest_frame().architecture().disassemble(address)[0]
    asm = ins["asm"].split(maxsplit=1)

    pwn_ins = PwndbgInstruction(None)
    pwn_ins.address = address
    pwn_ins.size = ins["length"]

    pwn_ins.mnemonic = asm[0].strip()
    pwn_ins.op_str = asm[1].strip() if len(asm) > 1 else ""

    pwn_ins.next = address + pwn_ins.size
    pwn_ins.target = pwn_ins.next

    pwn_ins.groups = []

    pwn_ins.condition = InstructionCondition.UNDETERMINED

    pwn_ins.annotation = None

    pwn_ins.operands = []

    return pwn_ins
