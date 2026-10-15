from __future__ import annotations

from collections.abc import Callable

from capstone6pwndbg import *  # noqa: F403
from capstone6pwndbg.m68k import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.assistant
import pwndbg.lib.disasm.helpers
from pwndbg.aglib.disasm.instruction import EnhancedOperand
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import MemoryDereferenceInfo
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE


def C_BIT(eflags: int) -> bool:
    return bool(eflags & (1 << 0))


def V_BIT(eflags: int) -> bool:
    return bool(eflags & (1 << 1))


def Z_BIT(eflags: int) -> bool:
    return bool(eflags & (1 << 2))


def N_BIT(eflags: int) -> bool:
    return bool(eflags & (1 << 3))


CONDITION_RESOLVERS: dict[int, Callable[[int], bool]] = {
    M68K_INS_BHI: lambda flags: not C_BIT(flags) and not Z_BIT(flags),
    M68K_INS_BLS: lambda flags: C_BIT(flags) or Z_BIT(flags),
    M68K_INS_BCC: lambda flags: not C_BIT(flags),
    M68K_INS_BCS: lambda flags: C_BIT(flags),
    M68K_INS_BNE: lambda flags: not Z_BIT(flags),
    M68K_INS_BEQ: lambda flags: Z_BIT(flags),
    M68K_INS_BVC: lambda flags: not V_BIT(flags),
    M68K_INS_BVS: lambda flags: V_BIT(flags),
    M68K_INS_BPL: lambda flags: not N_BIT(flags),
    M68K_INS_BMI: lambda flags: N_BIT(flags),
    # signed comparisons
    M68K_INS_BGE: lambda flags: N_BIT(flags) == V_BIT(flags),
    M68K_INS_BLT: lambda flags: N_BIT(flags) != V_BIT(flags),
    M68K_INS_BGT: lambda flags: not Z_BIT(flags) and (N_BIT(flags) == V_BIT(flags)),
    M68K_INS_BLE: lambda flags: Z_BIT(flags) or (N_BIT(flags) != V_BIT(flags)),
}


class M68kDisassemblyAssistant(pwndbg.aglib.disasm.assistant.DisassemblyAssistant):
    def __init__(self, architecture: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> None:
        super().__init__(architecture)

        self.resolve_op_value_handlers[M68K_OP_BR_DISP] = self._parse_br_disp

        self.register_name_aliases["a7"] = "sp"

        self.annotation_handlers: dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            M68K_INS_MOVE: self.handle_mov,
            # TODO: need to handle sign extension and stuff here
            # M68K_INS_MOVEA: self.handle_mov,
            M68K_INS_TST: self.handle_tst,
            M68K_INS_CMP: self.handle_cmp,
            M68K_INS_CMPI: self.handle_cmp,
            M68K_INS_CMPA: self.handle_cmp,
            M68K_INS_LEA: self.handle_lea,
        }

    def _parse_br_disp(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator | None
    ) -> int | None:
        disp = op.cs_op.br_disp.disp
        return instruction.address + 2 + disp

    def _handle_index_size(self, index_value: int, index_size: int) -> int:
        if index_size == 0:
            # Treat it as 16-bits and sign-extend up to 32-bits
            return pwndbg.lib.disasm.helpers.to_signed(index_value, 16)
        return index_value

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator | None
    ) -> int | None:
        mem, address_mode = op.cs_op.mem, op.cs_op.address_mode

        if instruction.id in (M68K_INS_JMP, M68K_INS_JSR):
            # While this may be typed as a memory operand, we don't necessarily want to dereference it
            # automatically, in the case of jumps
            # We do this so the generic _resolve_target handler resolves the target correctly
            # for these operands.
            op.should_dereference_memory_to_resolve = False

        # 3 and 4
        if address_mode in (M68K_AM_REGI_ADDR, M68K_AM_REGI_ADDR_POST_INC):
            return self._read_register(instruction, mem.base_reg, emu)

        # 5
        if address_mode == M68K_AM_REGI_ADDR_PRE_DEC:
            value = self._read_register(instruction, mem.base_reg, emu)
            if value is None:
                return None
            value -= instruction.cs_insn.op_size.size
            return value

        # 6
        if address_mode == M68K_AM_REGI_ADDR_DISP:
            value = self._read_register(instruction, mem.base_reg, emu)
            if value is None:
                return None
            value += mem.disp
            return value

        # 7
        if address_mode == M68K_AM_AREGI_INDEX_8_BIT_DISP:
            base_reg = self._read_register(instruction, mem.base_reg, emu)
            if base_reg is None:
                return None

            index_value = self._read_register(instruction, mem.index_reg, emu)
            if index_value is None:
                return None

            # Optionally sign extend
            index_value = self._handle_index_size(index_value, mem.index_size)
            index_value *= mem.scale if mem.scale != 0 else 1

            return base_reg + index_value + mem.disp

        # 8
        if address_mode == M68K_AM_AREGI_INDEX_BASE_DISP:
            base_reg = 0
            if mem.base_reg != 0:
                base_reg = self._read_register(instruction, mem.base_reg, emu)
                if base_reg is None:
                    return None

            index_value = 0
            if mem.index_reg != 0:
                index_value = self._read_register(instruction, mem.index_reg, emu)
                if index_value is None:
                    return None

                # Optionally sign extend
                index_value = self._handle_index_size(index_value, mem.index_size)
                index_value *= mem.scale if mem.scale != 0 else 1

            return base_reg + index_value + mem.in_disp

        # 9, 10, 14, 15
        if address_mode in (
            M68K_AM_MEMI_POST_INDEX,
            M68K_AM_MEMI_PRE_INDEX,
            M68K_AM_PC_MEMI_POST_INDEX,
            M68K_AM_PC_MEMI_PRE_INDEX,
        ):
            if mem.base_reg == M68K_REG_PC:
                base_value = instruction.address + 2
            elif mem.base_reg != 0:
                base_value = self._read_register(instruction, mem.base_reg, emu)
                if base_value is None:
                    return None
            else:
                base_value = 0

            index_value = 0
            if mem.index_reg != 0:
                index_value = self._read_register(instruction, mem.index_reg, emu)
                if index_value is None:
                    return None
                # Optionally sign extend
                index_value = self._handle_index_size(index_value, mem.index_size)
                index_value *= mem.scale if mem.scale != 0 else 1

            pointer_location_to_read = base_value + mem.in_disp
            if address_mode in (M68K_AM_MEMI_PRE_INDEX, M68K_AM_PC_MEMI_PRE_INDEX):
                pointer_location_to_read += index_value

            pointer_location_to_read &= pwndbg.aglib.arch.ptrmask
            indirect_value = self._read_memory(
                pointer_location_to_read, pwndbg.aglib.arch.ptrsize, instruction, emu
            )

            if indirect_value is None:
                return None

            if address_mode in (M68K_AM_MEMI_POST_INDEX, M68K_AM_PC_MEMI_POST_INDEX):
                indirect_value += index_value

            return (indirect_value + mem.out_disp) & pwndbg.aglib.arch.ptrmask

        # 11
        if address_mode == M68K_AM_PCI_DISP:
            return instruction.address + 2 + mem.disp

        # 12
        if address_mode == M68K_AM_PCI_INDEX_8_BIT_DISP:
            index_value = self._read_register(instruction, mem.index_reg, emu)
            if index_value is None:
                return None

            # Optionally sign extend
            index_value = self._handle_index_size(index_value, mem.index_size)
            index_value *= mem.scale if mem.scale != 0 else 1

            return instruction.address + 2 + mem.disp + index_value

        # 13
        if address_mode == M68K_AM_PCI_INDEX_BASE_DISP:
            base_value = instruction.address + 2 if mem.base_reg == M68K_REG_PC else 0

            index_value = 0
            if mem.index_reg != 0:
                index_value = self._read_register(instruction, mem.index_reg, emu)
                if index_value is None:
                    return None
                # Optionally sign extend
                index_value = self._handle_index_size(index_value, mem.index_size)
                index_value *= mem.scale if mem.scale != 0 else 1

            return base_value + mem.in_disp + index_value

        # 16
        if address_mode == M68K_AM_ABSOLUTE_DATA_SHORT:
            # Although this is encoded as an address, it is most likely
            # used as a value, such as in `pea` which pushes to the stack
            return mem.address

        # 17
        if address_mode == M68K_AM_ABSOLUTE_DATA_LONG:
            return mem.address

        return None

    @override
    def _resolve_used_value(
        self,
        value: int | None,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator | None,
        force_allow_process_read: bool = False,
    ) -> int | None:
        if value is None:
            return None

        if operand.should_dereference_memory_to_resolve:
            # Overload this call to use the correct read width
            # This is important because m68k is big endian,
            # so the read width will effect the logical integer value
            # passed back to us by the debugger
            read_size = instruction.cs_insn.op_size.size
            if read_size == 0:
                read_size = pwndbg.aglib.arch.ptrsize

            return self._read_memory(
                value,
                read_size,
                instruction,
                emu,
                force_allow_process_read=force_allow_process_read,
            )
        return super()._resolve_used_value(
            value, instruction, operand, emu, force_allow_process_read=force_allow_process_read
        )

    @override
    def _condition(
        self, instruction: PwndbgInstruction, emu: Emulator | None
    ) -> InstructionCondition:

        if instruction.id == M68K_INS_BRA:
            return InstructionCondition.UNCONDITIONAL

        condition_resolver = CONDITION_RESOLVERS.get(instruction.id)

        if condition_resolver is None:
            return InstructionCondition.UNCONDITIONAL

        flags = self._read_register_name(instruction, "ps", emu)

        if flags is None:
            # We can't reason about the value of flags register
            return InstructionCondition.UNDETERMINED_CONDITIONAL

        conditional = condition_resolver(flags)

        return InstructionCondition.TRUE if conditional else InstructionCondition.FALSE

    @override
    def _prepare(self, instruction: PwndbgInstruction, emu: Emulator | None) -> None:
        if instruction.id == M68K_INS_TRAP:
            instruction.groups.add(CS_GRP_INT)
            instruction.groups.remove(CS_GRP_JUMP)

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None) -> int | None:

        if instruction.id != M68K_INS_RTS:
            return super()._resolve_target(instruction, emu)

        if not self.can_reason_about_process_state():
            return super()._resolve_target(instruction, emu)

        # Get value from top of stack
        # TODO: deduplicate from x86? does that assume emulation too much?
        address = pwndbg.aglib.regs.sp

        if pwndbg.aglib.memory.peek(address):
            return int(
                pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.ppvoid, address)
            )

        # The RSP does not point to readable memory!
        instruction.target_memory_operand = MemoryDereferenceInfo(address, None, None)
        return None

    def handle_mov(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # m68k move is a very complicated instruction, even more so than x86's mov
        # The instructions can have a suffix, like
        # .b -> 1 byte
        # .w -> 2 bytes
        # .l -> 4 bytes
        #
        # If an instructions only writes 1 or 2 bytes, the upper bytes are left untouched
        # However this is only the case for "data" registers. "address" registers are signed-extended
        #
        # For example, you can do
        # - move.b $0(a2, d1.l), d0
        # Which takes a single byte at the specified address, and overwrites the bottom byte of that in d0

        source, destination = instruction.operands

        if source.type == CS_OP_MEM and destination.type == CS_OP_REG:
            # Load instruction
            self._common_load_annotator(
                instruction,
                emu,
                source.before_value,
                instruction.cs_insn.op_size.size,
                False,
                instruction.cs_insn.op_size.size,
                destination.str,
                source.str,
                partial_overwrite=(True, destination.reg),
            )
        elif destination.type == CS_OP_MEM and source.type != CS_OP_MEM:
            # Store instruction
            self._common_store_annotator(
                instruction,
                emu,
                destination.before_value,
                source.before_value,
                instruction.cs_insn.op_size.size,
                destination.str,
            )

        elif destination.type == CS_OP_REG:
            # Moving reg or immediate into register
            self._common_move_annotator(instruction, emu, flipped_operands=True)

    def handle_tst(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        op = instruction.operands[0]

        if (value := op.before_value_resolved) is not None:
            mask = (1 << (instruction.cs_insn.op_size.size * 8)) - 1
            value &= mask

            print_value = pwndbg.lib.pretty_print.int_to_string(value)
            instruction.annotation = f"{print_value} - 0"

    def handle_cmp(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        source, destination = instruction.operands

        if (source_value := source.before_value_resolved) is not None and (
            destination_value := destination.before_value_resolved
        ) is not None:
            mask = (1 << (instruction.cs_insn.op_size.size * 8)) - 1
            source_value &= mask
            destination_value &= mask

            print_left, print_right = pwndbg.lib.pretty_print.int_pair_to_string(
                source_value, destination_value
            )
            # Ex: "0x7f - 0x12" or "0xdffffdea + 0x8"
            instruction.annotation = f"{print_right} - {print_left}"

    def handle_lea(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Example: lea    rdx, [rax*8]
        source, destination = instruction.operands

        TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

        if source.before_value is not None:
            telescope_addresses = super()._telescope(
                source.before_value, TELESCOPE_DEPTH, instruction, emu
            )
            instruction.annotation = pwndbg.aglib.disasm.assistant.register_assign(
                destination.str,
                super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu),
            )

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator | None) -> None:
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)
