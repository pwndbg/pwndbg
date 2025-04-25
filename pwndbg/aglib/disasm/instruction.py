from __future__ import annotations

import typing
from collections import defaultdict
from enum import Enum
from typing import Dict
from typing import List
from typing import Protocol
from typing import Set

import pwnlib

# Reverse lookup tables for debug printing
from capstone import CS_AC
from capstone import CS_GRP
from capstone import CS_OP
from capstone import *  # noqa: F403
from capstone.aarch64 import AARCH64_INS_BL
from capstone.aarch64 import AARCH64_INS_BLR
from capstone.aarch64 import AARCH64_INS_BR
from capstone.arm import ARM_INS_TBB
from capstone.arm import ARM_INS_TBH
from capstone.loongarch import LOONGARCH_INS_ALIAS_JR
from capstone.loongarch import LOONGARCH_INS_B
from capstone.loongarch import LOONGARCH_INS_BL
from capstone.loongarch import LOONGARCH_INS_JIRL
from capstone.mips import MIPS_INS_ALIAS_B
from capstone.mips import MIPS_INS_ALIAS_BAL
from capstone.mips import MIPS_INS_B
from capstone.mips import MIPS_INS_BAL
from capstone.mips import MIPS_INS_BLTZAL
from capstone.mips import MIPS_INS_J
from capstone.mips import MIPS_INS_JAL
from capstone.mips import MIPS_INS_JALR
from capstone.mips import MIPS_INS_JALR_HB
from capstone.mips import MIPS_INS_JR
from capstone.ppc import PPC_INS_B
from capstone.ppc import PPC_INS_BA
from capstone.ppc import PPC_INS_BL
from capstone.ppc import PPC_INS_BLA
from capstone.riscv import RISCV_INS_C_J
from capstone.riscv import RISCV_INS_C_JAL
from capstone.riscv import RISCV_INS_C_JALR
from capstone.riscv import RISCV_INS_C_JR
from capstone.riscv import RISCV_INS_JAL
from capstone.riscv import RISCV_INS_JALR
from capstone.sparc import SPARC_INS_JMP
from capstone.sparc import SPARC_INS_JMPL
from capstone.systemz import SYSTEMZ_INS_B
from capstone.systemz import SYSTEMZ_INS_BAL
from capstone.systemz import SYSTEMZ_INS_BALR
from capstone.x86 import X86_INS_JMP
from capstone.x86 import X86Op
from typing_extensions import override

import pwndbg.dbg
from pwndbg.dbg import DisassembledInstruction

# Architecture specific instructions that mutate the instruction pointer unconditionally
# The Capstone RET and CALL groups are also used to filter CALL and RET types when we check for unconditional jumps,
# so we don't need to manually specify those for each architecture
UNCONDITIONAL_JUMP_INSTRUCTIONS: Dict[int, Set[int]] = {
    CS_ARCH_X86: {X86_INS_JMP},
    CS_ARCH_MIPS: {
        MIPS_INS_J,
        MIPS_INS_JR,
        MIPS_INS_JAL,
        MIPS_INS_JALR,
        MIPS_INS_JALR_HB,
        MIPS_INS_BAL,
        MIPS_INS_ALIAS_BAL,
        MIPS_INS_B,
        MIPS_INS_ALIAS_B,
    },
    CS_ARCH_SPARC: {SPARC_INS_JMP, SPARC_INS_JMPL},
    CS_ARCH_ARM: {
        ARM_INS_TBB,
        ARM_INS_TBH,
    },
    CS_ARCH_AARCH64: {AARCH64_INS_BL, AARCH64_INS_BLR, AARCH64_INS_BR},
    CS_ARCH_RISCV: {
        RISCV_INS_JAL,
        RISCV_INS_JALR,
        RISCV_INS_C_JAL,
        RISCV_INS_C_JALR,
        RISCV_INS_C_J,
        RISCV_INS_C_JR,
    },
    CS_ARCH_PPC: {PPC_INS_B, PPC_INS_BA, PPC_INS_BL, PPC_INS_BLA},
    CS_ARCH_SYSTEMZ: {SYSTEMZ_INS_B, SYSTEMZ_INS_BAL, SYSTEMZ_INS_BALR},
    CS_ARCH_LOONGARCH: {
        LOONGARCH_INS_B,
        LOONGARCH_INS_BL,
        LOONGARCH_INS_JIRL,
        LOONGARCH_INS_ALIAS_JR,
    },
}

# See: https://github.com/capstone-engine/capstone/issues/2448
BRANCH_AND_LINK_INSTRUCTIONS: Dict[int, Set[int]] = defaultdict(set)
BRANCH_AND_LINK_INSTRUCTIONS[CS_ARCH_MIPS] = {
    MIPS_INS_BAL,
    MIPS_INS_BLTZAL,
    MIPS_INS_JAL,
    MIPS_INS_JALR,
}

# Everything that is a CALL or a RET is a unconditional jump
GENERIC_UNCONDITIONAL_JUMP_GROUPS = {CS_GRP_CALL, CS_GRP_RET, CS_GRP_IRET}
# All branch-like instructions - jumps thats are non-call and non-ret - should have one of these two groups in Capstone
GENERIC_JUMP_GROUPS = {CS_GRP_JUMP, CS_GRP_BRANCH_RELATIVE}
# All Capstone jumps should have at least one of these groups
ALL_JUMP_GROUPS = GENERIC_JUMP_GROUPS | GENERIC_UNCONDITIONAL_JUMP_GROUPS

# All non-ret jumps
FORWARD_JUMP_GROUP = {CS_GRP_CALL} | GENERIC_JUMP_GROUPS


class InstructionCondition(Enum):
    # Conditional instruction, and action is taken
    TRUE = 1
    # Conditional instruction, but action is not taken
    FALSE = 2
    # Unconditional instructions (most instructions), or we cannot reason about the instruction
    UNDETERMINED = 3


def boolean_to_instruction_condition(condition: bool) -> InstructionCondition:
    return InstructionCondition.TRUE if condition else InstructionCondition.FALSE


class SplitType(Enum):
    NO_SPLIT = 1
    BRANCH_TAKEN = 2
    BRANCH_NOT_TAKEN = 3


# Only use within the instruction.__repr__ to give a nice output
CAPSTONE_ARCH_MAPPING_STRING = {
    CS_ARCH_ARM: "arm",
    CS_ARCH_AARCH64: "aarch64",
    CS_ARCH_X86: "x86",
    CS_ARCH_PPC: "powerpc",
    CS_ARCH_MIPS: "mips",
    CS_ARCH_SPARC: "sparc",
    CS_ARCH_RISCV: "RISCV",
    CS_ARCH_SYSTEMZ: "s390x",
    CS_ARCH_LOONGARCH: "loongarch",
}


# Interface for enhanced instructions - there are two implementations defined in this file
class PwndbgInstruction(Protocol):
    cs_insn: CsInsn
    address: int
    size: int
    mnemonic: str
    op_str: str
    groups: Set[int]
    id: int
    operands: List[EnhancedOperand]
    asm_string: str
    next: int
    target: int
    target_string: str | None
    target_const: bool | None
    condition: InstructionCondition
    declare_conditional: bool | None
    declare_is_unconditional_jump: bool
    force_unconditional_jump_target: bool
    annotation: str | None
    annotation_padding: int | None
    syscall: int | None
    syscall_name: str | None
    causes_branch_delay: bool
    split: SplitType
    emulated: bool

    @property
    def call_like(self) -> bool: ...

    @property
    def jump_like(self) -> bool: ...

    @property
    def has_jump_target(self) -> bool: ...

    @property
    def is_conditional_jump(self) -> bool: ...

    @property
    def is_unconditional_jump(self) -> bool: ...

    @property
    def is_conditional_jump_taken(self) -> bool: ...

    @property
    def bytes(self) -> bytearray: ...

    def op_find(self, op_type: int, position: int) -> EnhancedOperand: ...

    def op_count(self, op_type: int) -> int: ...


# This class is used to provide context to an instructions execution, used both
# in the disasm view output (see 'pwndbg.color.disasm.instruction()'), as well as for
# Pwndbg commands like "nextcall" that need to know the instructions target to set breakpoints
# The information in this class is backed by metadata from Capstone
class PwndbgInstructionImpl(PwndbgInstruction):
    def __init__(self, cs_insn: CsInsn) -> None:
        self.cs_insn: CsInsn = cs_insn
        """
        The underlying Capstone instruction object.
        Only the enhancement code should access the 'cs_insn' property
        """

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

        self.groups: Set[int] = set(cs_insn.groups)
        """
        Capstone instruction groups that we belong to.
        Groups that apply to all architectures: CS_GRP_INVALID | CS_GRP_JUMP | CS_GRP_CALL | CS_GRP_RET | CS_GRP_INT | CS_GRP_IRET | CS_GRP_PRIVILEGE | CS_GRP_BRANCH_RELATIVE
        """

        self.id: int = cs_insn.alias_id if cs_insn.is_alias else cs_insn.id
        """
        The underlying Capstone ID for the instruction
        If it's an alias, use the id of the alias

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
        # in pwndbg.aglib.disasm.arch.py
        # ***********

        self.asm_string: str = f"{self.mnemonic:<6} {self.op_str}"
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
        See 'condition' function in pwndbg.aglib.disasm.x86 for example on setting this.

        UNDETERMINED if we cannot reason about the condition, or if the instruction always executes unconditionally (most instructions).

        TRUE if the instruction has a conditional action, and we determine it is taken.

        FALSE if the instruction has a conditional action, and we know it is not taken.
        """

        self.declare_conditional: bool | None = None
        """
        This field is used to declare if the instruction is a conditional instruction.
        In most cases, we can determine this purely based on the instruction ID, and this field is irrelevent.
        However, in some arches, like Arm, the same instruction can be made conditional by certain instruction attributes.
        Ex:
            Arm, `bls` instruction. This is encoded as a `b` under the code, with an additional condition code field.
            In this case, sometimes a `b` instruction is unconditional (always branches), in other cases it is conditional.
            We use this field to disambiguate these cases.

        True if we manually determine this instruction is a conditional instruction
        False if it's not a conditional instruction
        None if we don't have a determination (most cases)
        """

        self.declare_is_unconditional_jump: bool = False
        """
        This field is used to declare that this instruction is an unconditional jump.
        Most of the time, we depend on Capstone groups to check for jump instructions.
        However, some instructions become branches depending on the operands,
        such as Arm `add`, `sub`, `ldr`, `pop`, where PC is the destination register

        In these cases, we want to forcefully state that this instruction mutates the PC, so we set this attribute to True.

        This helps in two cases:
        1. Disassembly splits
        2. Instructions like `stepuntilasm` work better, as they detect these as branches to stop at.
        """

        self.force_unconditional_jump_target: bool = False
        """
        This asserts that the .target attribute is the real target of the instruction.
        This is only relevent in the edge case that the target is the next instruction in memory (address + size).
        The normal check for "target" checks that the target is NOT the next address in memory, and here we can assert that even if that is the case,
        we know that the jump really does just go to where self.target is.
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

        self.syscall: int | None = None
        """
        The syscall number for this instruction, if it is a syscall. Otherwise None.
        """

        self.syscall_name: str | None = None
        """
        The syscall name as a string

        Ex: "openat", "read"
        """

        self.causes_branch_delay: bool = False
        """
        Whether or not this instruction has a single branch delay slot
        """

        self.split: SplitType = SplitType.NO_SPLIT
        """
        The type of split in the disasm display this instruction causes:

            NO_SPLIT            - no extra spacing between this and the next instruction
            BRANCH_TAKEN        - a newline with an arrow pointing down
            BRANCH_NOT_TAKEN    - an empty newline
        """

        self.emulated: bool = False
        """
        If the enhancement successfully used emulation for this instruction
        """

    @property
    def call_like(self) -> bool:
        """
        True if this is a call-like instruction, meaning either it's a CALL or a branch and link.

        Checking for the CS_GRP_CALL is insufficient, as there are many "branch and link" instructions that are not labeled as a call
        """
        return (
            CS_GRP_CALL in self.groups
            or self.id in BRANCH_AND_LINK_INSTRUCTIONS[self.cs_insn._cs.arch]
        )

    @property
    def jump_like(self) -> bool:
        """
        True if this instruction is "jump-like", such as a JUMP, CALL, or RET.
        Basically, the PC is set to some target by means of this instruction.

        It may still be a conditional jump - this property does not indicate whether the jump is taken or not.
        """
        return bool(self.groups & ALL_JUMP_GROUPS) or self.declare_is_unconditional_jump

    @property
    def has_jump_target(self) -> bool:
        """
        True if we have determined that this instruction can explicitly change the program counter, and
        we have determined the jump target.

        Edge case - the jump target MAY be the next address in memory - so we check force_unconditional_jump_target
        """
        # The second check ensures that if the target address is itself, it's a jump (infinite loop) and not something like `rep movsb` which repeats the same instruction.
        # Because capstone doesn't catch ALL cases of an instruction changing the PC, we don't have the `jump_like` in the first part of this check.
        return (
            self.target not in (None, self.address + self.size)
            and (self.target != self.address or self.jump_like)
        ) or self.force_unconditional_jump_target

    @property
    def is_conditional_jump(self) -> bool:
        """
        True if this instruction can change the program counter conditionally.

        This is used, in part, to determine if the instruction deserves a "checkmark" in the disasm view.

        This does not imply that we have resolved the .target
        """
        return (
            self.declare_conditional is not False
            and self.declare_is_unconditional_jump is False
            and bool(self.groups & GENERIC_JUMP_GROUPS)
            and self.id not in UNCONDITIONAL_JUMP_INSTRUCTIONS[self.cs_insn._cs.arch]
        )

    @property
    def is_unconditional_jump(self) -> bool:
        """
        True if we know the instruction can change the program counter, and does so unconditionally.

        This includes things like RET, CALL, and JMP (in x86).

        This property is used in enhancement to determine certain codepaths when resolving .next for this instruction.

        This does not imply that we have resolved the .target
        """
        return (
            bool(self.groups & GENERIC_UNCONDITIONAL_JUMP_GROUPS)
            or self.id in UNCONDITIONAL_JUMP_INSTRUCTIONS[self.cs_insn._cs.arch]
            or self.declare_is_unconditional_jump
            or self.declare_conditional is False
        )

    @property
    def is_conditional_jump_taken(self) -> bool:
        """
        True if this is a conditional jump, and we predicted that we will take the jump
        """
        # True if:
        # - We manually determined in .condition that we take the jump
        # - Or that emulation determined the .next to go somewhere and we didn't explicitely set .condition to False.
        #   Emulation can be incorrect, so we check the conditional for false to check if we manually override the emulator's decision
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

        info = f"""{self.mnemonic} {self.op_str} at {self.address:#x} (size={self.size}) (arch: {CAPSTONE_ARCH_MAPPING_STRING.get(self.cs_insn._cs.arch,None)})
        Bytes: {pwnlib.util.fiddling.enhex(self.bytes)}
        ID: {self.id}, {self.cs_insn.insn_name()}
        Capstone ID/Alias ID: {self.cs_insn.id} / {self.cs_insn.alias_id if self.cs_insn.is_alias else 'None'}
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
        Declare conditional: {self.declare_conditional}
        Declare unconditional jump: {self.declare_is_unconditional_jump}
        Force jump target: {self.force_unconditional_jump_target}
        Can change PC: {self.has_jump_target}
        Syscall: {self.syscall if self.syscall is not None else ""} {self.syscall_name if self.syscall_name is not None else "N/A"}
        Causes Delay slot: {self.causes_branch_delay}
        Split: {SplitType(self.split).name}
        Call-like: {self.call_like}"""

        # Hacky, but this is just for debugging
        if hasattr(self.cs_insn, "cc"):
            info += f"\n\tARM condition code: {self.cs_insn.cc}"
            info += f"\n\tThumb mode: {1 if self.cs_insn._cs._mode & CS_MODE_THUMB else 0}"

        return info


class EnhancedOperand:
    def __init__(self, cs_op):
        self.cs_op: typing.Any = cs_op
        """
        Underlying Capstone operand. Takes on a different value depending on the architecture.

        x86 = capstone.x86.X86Op, arm = capstone.arm.ArmOp, mips = capstone.mips.MipsOp
        """

        # ***********
        # The following member variables are set during instruction enhancement
        # in pwndbg.aglib.disasm.arch.py
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

        self.before_value_no_modifiers: int | None = None
        """
        This is a special field used in some architectures that allow operand modifiers, such as shifts and extends in Arm.
        Capstone bundles the modifier with the operand, and when we are resolving concrete operand values, we apply the modifier.
        However, in some annotations we need to un-modified raw register value, which is what this field is for.
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


# Represents a disassembled instruction
# Conforms to the PwndbgInstruction interface
class ManualPwndbgInstruction(PwndbgInstruction):
    def __init__(self, address: int) -> None:
        """
        This class provides an implementation of PwndbgInstruction for cases where the architecture
        at hand is not supported by the Capstone disassembler. The backing information is sourced from
        GDB/LLDB's built-in disassemblers.

        Instances of this class do not go through the 'enhancement' process due to lacking important information provided by Capstone.
        As a result of this, some of the methods raise NotImplementedError, because if they are called it indicates a bug elsewhere in the codebase.
        """
        ins: DisassembledInstruction = pwndbg.dbg.selected_inferior().disasm(address)
        asm = ins["asm"].split(maxsplit=1)

        # The enhancement code assumes this value exists.
        # However, a ManualPwndbgInstruction should never be used in the enhancement code.
        self.cs_insn: CsInsn = None

        self.address = address
        self.size = ins["length"]

        self.mnemonic = asm[0].strip()
        self.op_str = asm[1].strip() if len(asm) > 1 else ""
        self.groups = set()

        # Set Capstone ID to -1
        self.id = -1

        self.operands = []

        self.asm_string = f"{self.mnemonic:<6} {self.op_str}"

        self.next = address + self.size
        self.target = self.next
        self.target_string = None
        self.target_const = None

        self.condition = InstructionCondition.UNDETERMINED

        self.declare_conditional = None
        self.declare_is_unconditional_jump = False
        self.force_unconditional_jump_target = False

        self.annotation = None

        self.annotation_padding = None

        self.syscall = None
        self.syscall_name = None

        self.causes_branch_delay = False

        self.split = SplitType.NO_SPLIT

        self.emulated = False

    @property
    def bytes(self) -> bytearray:
        # GDB simply doesn't provide us with the raw bytes.
        # However, it is important that this returns a valid bytearray,
        # since the disasm code indexes this for nearpc-num-opcode-bytes.
        return bytearray()

    @property
    def call_like(self) -> bool:
        return False

    @property
    def jump_like(self) -> bool:
        return False

    @property
    def has_jump_target(self) -> bool:
        return False

    @property
    def is_conditional_jump(self) -> bool:
        return False

    @property
    def is_unconditional_jump(self) -> bool:
        return False

    @property
    def is_conditional_jump_taken(self) -> bool:
        return False

    @override
    def op_find(self, op_type: int, position: int) -> EnhancedOperand:
        # raise NotImplementedError, because if this is called it indicates a bug elsewhere in the codebase.
        # ManualPwndbgInstruction should not go through the enhancement process, where this would be called.
        raise NotImplementedError

    @override
    def op_count(self, op_type: int) -> int:
        raise NotImplementedError
