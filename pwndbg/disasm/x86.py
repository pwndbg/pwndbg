from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403

import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.color.memory as MemoryColor
import pwndbg.color.message as MessageColor
import pwndbg.disasm.arch
import pwndbg.enhance
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo
from pwndbg.disasm.instruction import EnhancedOperand
from pwndbg.disasm.instruction import InstructionCondition
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}


# Capstone operand type for x86 is capstone.x86.X86Op
# This type has a .size field, which indicates the operand read/write size in bytes
# Ex: dword ptr [RDX] has size = 4
# Ex: AL has size = 1
# Access through EnhancedOperand.cs_op.size


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
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
            # ADD
            X86_INS_ADD: self.handle_add,
            # SUB
            X86_INS_SUB: self.handle_sub,
            # CMP
            X86_INS_CMP: self.handle_cmp,
            # TEST
            X86_INS_TEST: self.handle_test,
            # XOR
            X86_INS_XOR: self.handle_xor,
            # AND
            X86_INS_AND: self.handle_and,
            # INC and DEC
            X86_INS_INC: self.handle_inc,
            X86_INS_DEC: self.handle_dec,
        }

    def handle_mov(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        # Read from right operand
        if right.before_value is not None:
            TELESCOPE_DEPTH = max(0, int(pwndbg.gdblib.config.disasm_telescope_depth))

            # +1 to ensure we telescope enough to read at least one address for the last "elif" below
            telescope_addresses = super()._telescope(
                right.before_value,
                TELESCOPE_DEPTH + 1,
                instruction,
                right,
                emu,
                read_size=right.cs_op.size,
            )
            if not telescope_addresses:
                return

            # MOV [MEM], REG or IMM
            if (
                left.type == CS_OP_MEM and left.before_value is not None
            ):  # right.type must then be either CS_OP_REG or CS_OP_IMM. Cannot MOV mem to mem
                # If the memory isn't mapped, we will segfault
                if not pwndbg.gdblib.memory.peek(left.before_value):
                    instruction.annotation = MessageColor.error(
                        f"<Cannot dereference [{MemoryColor.get(left.before_value)}]>"
                    )
                else:
                    instruction.annotation = f"{left.str} => {super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)}"

            # MOV REG, REG or IMM
            elif left.type == CS_OP_REG and right.type in (CS_OP_REG, CS_OP_IMM):
                instruction.annotation = f"{left.str} => {super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)}"

            # MOV REG, [MEM]
            elif left.type == CS_OP_REG and right.type == CS_OP_MEM:
                # There are many cases we need to consider if there is a mov from a dereference memory location into a register
                # Were we able to reason about the memory address, and dereference it?
                # Does the resolved memory address actual point into memory?

                # right.before_value should be a pointer in this context. If we telescoped and still returned just the value itself,
                # it indicates that the dereference likely segfaults

                if not pwndbg.gdblib.memory.peek(right.before_value):
                    telescope_print = MessageColor.error(
                        f"<Cannot dereference [{MemoryColor.get(right.before_value)}]>"
                    )
                elif len(telescope_addresses) == 1:
                    # If only one address, and we didn't telescope, it means we couldn't reason about the dereferenced memory
                    # Simply display the address

                    # As an example, this path is taken for the following case:
                    # mov rdi, qword ptr [rip + 0x17d40] where the resolved memory address is in writeable memory,
                    # and we are not emulating. This means we cannot savely dereference (if PC is not at the current instruction address)
                    telescope_print = None
                else:
                    # Start showing at dereferenced by, hence the [1:]
                    telescope_print = f"{super()._telescope_format_list(telescope_addresses[1:], TELESCOPE_DEPTH, emu)}"

                if telescope_print is not None:
                    instruction.annotation = f"{left.str}, {right.str} => {telescope_print}"
                else:
                    instruction.annotation = f"{left.str}, {right.str}"

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

        TELESCOPE_DEPTH = max(0, int(pwndbg.gdblib.config.disasm_telescope_depth))

        if right.before_value is not None:
            telescope_addresses = super()._telescope(
                right.before_value, TELESCOPE_DEPTH, instruction, right, emu
            )
            instruction.annotation = f"{left.str} => {super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)}"

    def handle_xchg(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        if left.before_value_resolved is not None and right.before_value_resolved is not None:
            # Display the exchanged values. Doing it this way (instead of using .after_value) allows this to work without emulation
            # Don't telescope here for the sake of screen space
            instruction.annotation = f"{left.str} => {MemoryColor.get_address_or_symbol(right.before_value_resolved)}, {right.str} => {MemoryColor.get_address_or_symbol(left.before_value_resolved)}"

    def handle_pop(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        pc_is_at_instruction = self.can_reason_about_process_state(instruction)

        if len(instruction.operands) != 1:
            return

        reg_operand = instruction.operands[0]

        # It is possible to pop [0xdeadbeef] and pop dword [esp], but this only handles popping into a register
        if reg_operand.type == CS_OP_REG:
            if emu and reg_operand.after_value is not None:
                # After emulation, the register has taken on the popped value
                instruction.annotation = f"{reg_operand.str} => {MemoryColor.get_address_and_symbol(reg_operand.after_value)}"
            elif pc_is_at_instruction:
                # Attempt to read from the stop of the stack
                try:
                    value = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.regs.sp)
                    instruction.annotation = (
                        f"{reg_operand.str} => {MemoryColor.get_address_and_symbol(value)}"
                    )
                except Exception:
                    pass

    def handle_add_sub_handler(
        self, instruction: PwndbgInstruction, emu: Emulator, char_to_separate_operands: str
    ) -> None:
        # char_to_separate_operands = "+" or "-"
        left, right = instruction.operands

        # "a + b" or "a - b"
        plus_string = ""

        # This path set plus_string to "op1_value + op2_value" (or with a minus sign)
        if left.before_value_resolved is not None and right.before_value_resolved is not None:
            print_left, print_right = pwndbg.enhance.format_small_int_pair(
                left.before_value_resolved, right.before_value_resolved
            )

            plus_string = f"{print_left} {char_to_separate_operands} {print_right}"

        if left.after_value_resolved is not None:
            instruction.annotation = f"{left.str} => {MemoryColor.get_address_and_symbol(left.after_value_resolved)} ({plus_string})"
        elif plus_string:
            # We didn't use emulation to determine the result - still display the operands
            instruction.annotation = f"{left.str} => {plus_string}"

    def handle_add(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Same output as addition, showing the result
        self.handle_add_sub_handler(instruction, emu, "+")

    def handle_sub(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Same output as addition, showing the result
        self.handle_add_sub_handler(instruction, emu, "-")

    # Only difference is one character. - for cmp, & for test
    def handle_cmp_test_handler(
        self, instruction: PwndbgInstruction, emu: Emulator, char_to_separate_operands: str
    ) -> None:
        # cmp with memory, register, and intermediate operands can be used in many combinations
        # This function handles all combinations
        left, right = instruction.operands

        if left.before_value_resolved is not None and right.before_value_resolved is not None:
            print_left, print_right = pwndbg.enhance.format_small_int_pair(
                left.before_value_resolved, right.before_value_resolved
            )
            instruction.annotation = f"{print_left} {char_to_separate_operands} {print_right}"

            if emu:
                eflags_bits = pwndbg.gdblib.regs.flags["eflags"]
                emu_eflags = emu.read_register("eflags")
                eflags_formatted = C.format_flags(emu_eflags, eflags_bits)

                SPACES = 5
                instruction.annotation += " " * SPACES + f"EFLAGS => {eflags_formatted}"

    def handle_cmp(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        self.handle_cmp_test_handler(instruction, emu, "-")

    def handle_test(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        self.handle_cmp_test_handler(instruction, emu, "&")

    def handle_xor(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        # If zeroing the register with XOR A, A. Can reason about this no matter where the instruction is
        if left.type == CS_OP_REG and right.type == CS_OP_REG and left.reg == right.reg:
            instruction.annotation = f"{left.str} => 0"
        else:
            if left.after_value_resolved is not None:
                instruction.annotation = f"{left.str} => {left.after_value_resolved}"

    def handle_and(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        left, right = instruction.operands

        if left.after_value_resolved is not None:
            instruction.annotation = f"{left.str} => {MemoryColor.get(left.after_value_resolved)}"

    def handle_inc(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # INC operand can be REG or [MEMORY]
        operand = instruction.operands[0]

        if operand.after_value_resolved is not None:
            instruction.annotation = f"{operand.str} => {MemoryColor.get_address_and_symbol(operand.after_value_resolved)}"

    def handle_dec(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        self.handle_inc(instruction, emu)

    # Override
    def set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    # Override
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
            return self._read_memory(value, operand.cs_op.size, instruction, operand, emu)
        else:
            return super()._resolve_used_value(value, instruction, operand, emu)

    # Override
    def _read_register(self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator):
        # operand_id is the ID internal to Capstone

        if operand_id == X86_REG_RIP:
            # Ex: lea    rax, [rip + 0xd55]
            # We can reason RIP no matter the current pc
            return instruction.address + instruction.size
        else:
            return super()._read_register(instruction, operand_id, emu)

    # Override
    def _parse_memory(self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator):
        # Get memory address (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55. Does not dereference)
        target = 0

        # There doesn't appear to be a good way to read from segmented
        # addresses within GDB.
        if op.mem.segment != 0:
            return None

        if op.mem.base != 0:
            base = self._read_register(instruction, op.mem.base, emu)
            if base is None:
                return None
            target += base

        if op.mem.disp != 0:
            target += op.mem.disp

        if op.mem.index != 0:
            scale = op.mem.scale
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            target += scale * index

        return target

    # Override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        # Only handle 'ret', otherwise fallback to default implementation
        if X86_INS_RET != instruction.id or len(instruction.operands) > 1:
            return super()._resolve_target(instruction, emu, call=call)

        # Stop disassembling at RET if we won't know where it goes to without emulation
        if instruction.address != pwndbg.gdblib.regs.pc:
            return super()._resolve_target(instruction, emu, call=call)

        # Otherwise, resolve the return on the stack
        pop = 0
        if instruction.operands:
            pop = instruction.operands[0].before_value

        address = (pwndbg.gdblib.regs.sp) + (pwndbg.gdblib.arch.ptrsize * pop)

        if pwndbg.gdblib.memory.peek(address):
            return int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, address))

    # Override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        # JMP is unconditional
        if instruction.id in (X86_INS_JMP, X86_INS_RET, X86_INS_CALL):
            return InstructionCondition.UNDETERMINED

        # We can't reason about anything except the current instruction
        if instruction.address != pwndbg.gdblib.regs.pc:
            return InstructionCondition.UNDETERMINED

        efl = pwndbg.gdblib.regs.eflags
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

    # Currently not used
    def memory_string_with_components_resolved(
        self, instruction: PwndbgInstruction, op: EnhancedOperand
    ):
        # Example: [RSP + RCX*4 - 100] would return "[0x7ffd00acf230 + 8+4 - 100]"
        arith = False
        segment = op.mem.segment
        disp = op.mem.disp
        base = op.mem.base
        index = op.mem.index
        scale = op.mem.scale
        sz = ""

        if segment != 0:
            sz += f"{instruction.cs_insn.reg_name(segment)}:"

        if base != 0:
            sz += instruction.cs_insn.reg_name(base)
            arith = True

        if index != 0:
            if arith:
                sz += " + "

            index = pwndbg.gdblib.regs[instruction.cs_insn.reg_name(index)]
            sz += f"{index}*{scale:#x}"
            arith = True

        if disp != 0:
            if arith and disp < 0:
                sz += " - "
            elif arith and disp >= 0:
                sz += " + "
            sz += "%#x" % abs(disp)

        return f"[{sz}]"


assistant = DisassemblyAssistant("i386")
assistant = DisassemblyAssistant("x86-64")
