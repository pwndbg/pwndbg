from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict
from typing import Tuple

from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.typeinfo
import pwndbg.chain
import pwndbg.color.memory as MemoryColor
import pwndbg.color.message as MessageColor
import pwndbg.enhance
from pwndbg.aglib.disasm.arch import memory_or_register_assign
from pwndbg.aglib.disasm.arch import register_assign
from pwndbg.aglib.disasm.instruction import EnhancedOperand
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

X86_MATH_INSTRUCTIONS = {
    X86_INS_ADD: "+",
    X86_INS_SUB: "-",
    X86_INS_AND: "&",
    X86_INS_OR: "|",
}

# Capstone operand type for x86 is capstone.x86.X86Op
# This type has a .size field, which indicates the operand read/write size in bytes
# Ex: dword ptr [RDX] has size = 4
# Ex: AL has size = 1
# Access through EnhancedOperand.cs_op.size


# This class handles enhancement for x86 and x86_64. This is because Capstone itself
# represents both architectures using the same class
class X86DisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            X86_INS_MOV: self.handle_mov,
            X86_INS_MOVABS: self.handle_mov,
            X86_INS_MOVZX: self.handle_mov,
            X86_INS_MOVD: self.handle_mov,
            X86_INS_MOVQ: self.handle_mov,
            X86_INS_MOVSXD: self.handle_mov,
            X86_INS_MOVSX: self.handle_mov,
            # VMOVAPS
            X86_INS_MOVAPS: self.handle_vmovaps,
            X86_INS_VMOVAPS: self.handle_vmovaps,
            # LEA
            X86_INS_LEA: self.handle_lea,
            # XCHG
            X86_INS_XCHG: self.handle_xchg,
            # POP
            X86_INS_POP: self.handle_pop,
            # CMP
            X86_INS_CMP: self._common_cmp_annotator_builder("eflags", "-"),
            # TEST
            X86_INS_TEST: self._common_cmp_annotator_builder("eflags", "&"),
            # XOR
            X86_INS_XOR: self.handle_xor,
            # INC and DEC
            X86_INS_INC: self.handle_inc,
            X86_INS_DEC: self.handle_dec,
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in X86_MATH_INSTRUCTIONS:
            self._common_binary_op_annotator(
                instruction,
                emu,
                instruction.operands[0],
                instruction.operands[0].before_value_resolved,
                instruction.operands[1].before_value_resolved,
                X86_MATH_INSTRUCTIONS[instruction.id],
                instruction.operands[0].type == CS_OP_MEM,
            )
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    def handle_mov(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        # If this is a LOAD operation - MOV REG, [MEM]
        if left.type == CS_OP_REG and right.type == CS_OP_MEM:
            self._common_load_annotator(
                instruction,
                emu,
                right.before_value,
                right.cs_op.size,
                False,
                right.cs_op.size,
                left.str,
                right.str,
            )
        elif left.type == CS_OP_MEM:
            # Store operation, MOV [MEM], REG|IMM
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
                right.cs_op.size,
                instruction.operands[0].str,
            )
        elif left.type == CS_OP_REG and right.before_value is not None:
            # MOV REG, REG|IMM
            self._common_move_annotator(instruction, emu)

    def handle_vmovaps(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # If the source or destination is in memory, it must be aligned to:
        #  16 bytes for SSE, 32 bytes for AVX, 64 bytes for AVX-512
        # https://www.felixcloutier.com/x86/movaps
        # This displays a warning that the memory address is not aligned
        # movaps xmmword ptr [rsp + 0x60], xmm1

        left, right = instruction.operands

        mem_operand = (
            left if left.type == CS_OP_MEM else (right if right.type == CS_OP_MEM else None)
        )

        if mem_operand and mem_operand.before_value is not None:
            # operand.size is the width of memory in bytes (128, 256, or 512 bits = 16, 32, 64 bytes).
            # Pointer must be aligned to that memory width
            alignment_mask = mem_operand.cs_op.size - 1

            if mem_operand.before_value & alignment_mask != 0:
                instruction.annotation = MessageColor.error(
                    f"<[{MemoryColor.get(mem_operand.before_value)}] not aligned to {mem_operand.cs_op.size} bytes>"
                )

    def handle_lea(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Example: lea    rdx, [rax*8]
        left, right = instruction.operands

        TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

        if right.before_value is not None:
            telescope_addresses = super()._telescope(
                right.before_value, TELESCOPE_DEPTH, instruction, emu
            )
            instruction.annotation = register_assign(
                left.str, super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)
            )

    def handle_xchg(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        if left.before_value_resolved is not None and right.before_value_resolved is not None:
            # Display the exchanged values. Doing it this way (instead of using .after_value) allows this to work without emulation
            # Don't telescope here for the sake of screen space
            instruction.annotation = (
                memory_or_register_assign(
                    left.str,
                    MemoryColor.get_address_or_symbol(right.before_value_resolved),
                    left.type == CS_OP_MEM,
                )
                + ", "
                + memory_or_register_assign(
                    right.str,
                    MemoryColor.get_address_or_symbol(left.before_value_resolved),
                    right.type == CS_OP_MEM,
                )
            )

    def handle_pop(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        pc_is_at_instruction = self.can_reason_about_process_state(instruction)

        if len(instruction.operands) != 1:
            return

        reg_operand = instruction.operands[0]

        # It is possible to pop [0xdeadbeef] and pop dword [esp], but this only handles popping into a register
        if reg_operand.type == CS_OP_REG:
            if emu and reg_operand.after_value is not None:
                # After emulation, the register has taken on the popped value
                instruction.annotation = register_assign(
                    reg_operand.str, MemoryColor.get_address_and_symbol(reg_operand.after_value)
                )
            elif pc_is_at_instruction:
                # Attempt to read from the top of the stack
                try:
                    value = pwndbg.aglib.memory.pvoid(pwndbg.aglib.regs.sp)
                    instruction.annotation = register_assign(
                        reg_operand.str, MemoryColor.get_address_and_symbol(value)
                    )
                except Exception:
                    pass

    def handle_xor(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        # If zeroing the register with XOR A, A. Can reason about this no matter where the instruction is
        if left.type == CS_OP_REG and right.type == CS_OP_REG and left.reg == right.reg:
            instruction.annotation = register_assign(left.str, "0")
        else:
            self._common_binary_op_annotator(
                instruction,
                emu,
                instruction.operands[0],
                instruction.operands[0].before_value_resolved,
                instruction.operands[1].before_value_resolved,
                "^",
            )

    def handle_inc(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # INC operand can be REG or [MEMORY]
        operand = instruction.operands[0]

        if operand.after_value_resolved is not None:
            instruction.annotation = memory_or_register_assign(
                operand.str,
                MemoryColor.get_address_and_symbol(operand.after_value_resolved),
                operand.type == CS_OP_MEM,
            )

    def handle_dec(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        self.handle_inc(instruction, emu)

    @override
    def _resolve_used_value(
        self,
        value: int | None,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
    ) -> int | None:
        if value is None:
            return None

        if operand.type == CS_OP_MEM:
            return self._read_memory(value, operand.cs_op.size, instruction, emu)
        else:
            return super()._resolve_used_value(value, instruction, operand, emu)

    @override
    def _read_register(self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator):
        # operand_id is the ID internal to Capstone

        if operand_id == X86_REG_RIP:
            # Ex: lea    rax, [rip + 0xd55]
            # We can reason RIP no matter the current pc
            return instruction.address + instruction.size
        else:
            return super()._read_register(instruction, operand_id, emu)

    @override
    def _parse_memory(self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator):
        # Get memory address (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55. Does not dereference)
        if op.mem.segment != 0:
            if op.mem.segment == X86_REG_FS:
                if (seg_base := pwndbg.aglib.regs.fsbase) is None:
                    return None
            elif op.mem.segment == X86_REG_GS:
                if (seg_base := pwndbg.aglib.regs.gsbase) is None:
                    return None
            else:
                return None
        else:
            seg_base = 0

        if op.mem.base != 0:
            mem_base = self._read_register(instruction, op.mem.base, emu)
            if mem_base is None:
                return None
        else:
            mem_base = 0

        if op.mem.index != 0:
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            scale = op.mem.scale * index
        else:
            scale = 0

        return seg_base + mem_base + op.mem.disp + scale

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        # Only handle 'ret', otherwise fallback to default implementation
        if X86_INS_RET != instruction.id or len(instruction.operands) > 1:
            return super()._resolve_target(instruction, emu)

        # Stop disassembling at RET if we won't know where it goes to without emulation
        if instruction.address != pwndbg.aglib.regs.pc:
            return super()._resolve_target(instruction, emu)

        # Otherwise, resolve the return on the stack
        pop = instruction.operands[0].before_value if instruction.operands else 0

        address = (pwndbg.aglib.regs.sp) + (pwndbg.aglib.arch.ptrsize * pop)

        if pwndbg.aglib.memory.peek(address):
            return int(
                pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.ppvoid, address)
            )

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        # JMP is unconditional
        if instruction.id in (X86_INS_JMP, X86_INS_RET, X86_INS_CALL):
            return InstructionCondition.UNDETERMINED

        # We can't reason about anything except the current instruction
        if instruction.address != pwndbg.aglib.regs.pc:
            return InstructionCondition.UNDETERMINED

        efl = pwndbg.aglib.regs.eflags
        if efl is None:
            return InstructionCondition.UNDETERMINED

        cf = efl & (1 << 0)
        pf = efl & (1 << 2)
        # af = efl & (1 << 4)
        zf = efl & (1 << 6)
        sf = efl & (1 << 7)
        of = efl & (1 << 11)

        conditional = {
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

        if conditional is None:
            return InstructionCondition.UNDETERMINED

        return InstructionCondition.TRUE if bool(conditional) else InstructionCondition.FALSE

    @override
    def _get_syscall_arch_info(self, instruction: PwndbgInstruction) -> Tuple[str, str]:
        # Since this class handles both x86 and x86_64, we need to choose the correct
        # syscall arch depending on the instruction being executed.

        # On x86_x64 `syscall` and `int <value>` instructions are in CS_GRP_INT
        # but only `syscall` and `int 0x80` actually execute syscalls on Linux.
        # So here, we return no syscall name for other instructions and we also
        # handle a case when 32-bit syscalls are executed on x64
        mnemonic = instruction.mnemonic
        if mnemonic == "syscall":
            return ("x86-64", "rax")

        # On x86, the syscall_arch is already i386, so its all fine
        # On x64 the int 0x80 instruction executes 32-bit syscalls from i386
        # We read .imm directly, because at this point we haven't enhanced the operands with values
        if mnemonic == "int" and instruction.operands[0].imm == 0x80:
            return ("i386", "eax")

        return (None, None)

    # Currently not used
    def memory_string_with_components_resolved(
        self, instruction: PwndbgInstruction, op: EnhancedOperand
    ):
        # Example: [RSP + RCX*4 - 100] would return "[0x7ffd00acf230 + 8+4 - 100]"
        segment = op.mem.segment
        disp = op.mem.disp
        base = op.mem.base
        index = op.mem.index
        sz = ""

        if segment != 0:
            sz += f"{instruction.cs_insn.reg_name(segment)}:"

        if base != 0:
            sz += instruction.cs_insn.reg_name(base)
            arith = True
        else:
            arith = False

        if index != 0:
            if arith:
                sz += " + "

            index = pwndbg.aglib.regs[instruction.cs_insn.reg_name(index)]
            sz += f"{index}*{op.mem.scale:#x}"
            arith = True

        if disp != 0:
            if arith:
                if disp < 0:
                    sz += " - "
                else:
                    sz += " + "
            sz += f"{abs(disp):#x}"

        return f"[{sz}]"
