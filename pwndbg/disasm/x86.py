from __future__ import annotations
from typing import Callable

from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403

from pwndbg.emu.emulator import Emulator 
import pwndbg.color.context as C
import pwndbg.color.memory as MemoryColor
import pwndbg.color.message as MessageColor
import pwndbg.chain
import pwndbg.enhance

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

TELESCOPE_DEPTH = 3

# Operand type is capstone.x86.X86Op
class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):

    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.set_info_string_handlers: dict[int, Callable[[CsInsn, Emulator], None]] = {
            # MOV
            X86_INS_MOV: self.handle_mov_set_info,
            X86_INS_MOVABS: self.handle_mov_set_info,
            X86_INS_MOVZX: self.handle_mov_set_info,
            X86_INS_MOVD: self.handle_mov_set_info,
            X86_INS_MOVQ: self.handle_mov_set_info,
            X86_INS_MOVSXD: self.handle_mov_set_info,
            X86_INS_MOVSX: self.handle_mov_set_info,

            # LEA
            X86_INS_LEA: self.handle_lea_set_info,

            # POP
            X86_INS_POP: self.handle_pop_set_info,

            # ADD
            X86_INS_ADD: self.handle_add_set_info,

            # SUB
            X86_INS_SUB: self.handle_sub_set_info,

            # CMP
            X86_INS_CMP: self.handle_cmp_set_info,

            # TEST
            X86_INS_TEST: self.handle_test_set_info,

            # XOR
            X86_INS_XOR: self.handle_xor_set_info,

            # INC and DEC
            X86_INS_INC: self.handle_inc_set_info,
            X86_INS_DEC: self.handle_dec_set_info,

        }

    def can_reason_about_process_state(self, instruction: CsInsn) -> bool:
        return instruction.address == pwndbg.gdblib.regs.pc
    
    def handle_mov_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        left, right = instruction.operands
        
        # Read from right operand
        if right.before_value is not None:

            telescope_addresses, did_telescope = super().telescope(right.before_value, TELESCOPE_DEPTH, instruction, right, emu)
            if not telescope_addresses:
                return
            
            if left.type == CS_OP_MEM and left.before_value is not None: # right.type must then be either CS_OP_REG or CS_OP_IMM. Cannot MOV mem to mem
                instruction.info_string = f"[{MemoryColor.get(left.before_value)}] => {super().telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu, did_telescope)}"

            elif left.type == CS_OP_REG and right.type in (CS_OP_REG, CS_OP_IMM):
                regname = C.register_changed(C.register(left.str.upper()))
                instruction.info_string = f"{regname} => {super().telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu, did_telescope)}"
            
            elif left.type == CS_OP_REG and right.type == CS_OP_MEM:
                # There are many cases we need to consider if there is a mov from a dereference memory location into a register
                # Were we able to reason about the memory address, and dereference it?
                # Does the resolved memory address actual point into memory?
                
                regname = C.register_changed(C.register(left.str.upper()))
                
                # right.before_value should be a pointer in this context. If we telescoped and still returned just the value itself,
                # it indicates that the dereference likely segfaults
                if len(telescope_addresses) == 1 and did_telescope:
                    telescope_print = MessageColor.error("<Cannot dereference>")
                elif len(telescope_addresses) == 1:
                    # If only one address, and we didn't telescope, it means we couldn't reason about the dereferenced memory
                    # Simply display the address

                    # This path is taken for the following case:
                    # Ex: mov rdi, qword ptr [rip + 0x17d40] where the resolved memory address is in writeable memory,
                    # and we are not emulating
                    telescope_print = None
                else:
                    # Start showing at dereferenced by, hence the [1:]
                    telescope_print = f"{super().telescope_format_list(telescope_addresses[1:], TELESCOPE_DEPTH, emu, did_telescope)}"

                if telescope_print is not None:
                    instruction.info_string = f"{regname}, [{MemoryColor.get(right.before_value)}] => {telescope_print}"
                else:
                    instruction.info_string = f"{regname}, [{MemoryColor.get(right.before_value)}]"
    
    def handle_lea_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        # Example: lea    rdx, [rax*8]
        left, right = instruction.operands
        if right.before_value is not None:
            regname = C.register_changed(C.register(left.str.upper()))

            telescope_addresses, did_telescope = super().telescope(right.before_value, TELESCOPE_DEPTH, instruction, right, emu)
            instruction.info_string = f"{regname} => {super().telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu, did_telescope)}"

    def handle_pop_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        pc_is_at_instruction = self.can_reason_about_process_state(instruction)

        if len(instruction.operands) != 1:
            return
        
        reg_operand = instruction.operands[0]

        # It is possible to pop [0xdeadbeef] and pop dword [esp], but this only handles popping into a register
        if reg_operand.type == CS_OP_REG:
            if emu and reg_operand.after_value is not None:
                # After emulation, the register has taken on the popped value
                regname = C.register_changed(C.register(reg_operand.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get(reg_operand.after_value)}"
            elif pc_is_at_instruction:
                # Attempt to read from the stop of the stack
                try:
                    value = pwndbg.gdblib.memory.pvoid(pwndbg.gdblib.regs.sp)
                    regname = C.register_changed(C.register(reg_operand.str.upper()))
                    instruction.info_string = f"{regname} => {MemoryColor.get(value)}"
                except Exception as e:
                    print("ERROR", e)
                    pass
        
    def handle_add_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        left, right = instruction.operands

        # This may return None if cannot dereference memory (or after_value is None).
        left_actual = super().resolve_used_value(left.after_value, instruction, left, emu)

        if left_actual is not None:
            if left.type == CS_OP_REG:
                regname = C.register_changed(C.register(left.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get_address_and_symbol(left.after_value)}"
            elif left.type == CS_OP_MEM:
                instruction.info_string = f"[{MemoryColor.get(left.before_value)}] => {MemoryColor.get_address_and_symbol(left.after_value)}"

    def handle_sub_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        # Same output as addition, showing the result
        self.handle_add_set_info(instruction, emu)
    
    # Only difference is one character. - for cmp, & for test
    def handle_cmp_test_handler(self, instruction: CsInsn, emu: Emulator, char_to_seperate_operands: str) -> None:
        # cmp with memory, register, and intermediate operands can be used in many combinations
        # This function handles all combinations
        left, right = instruction.operands

        # These may return None if cannot dereference memory (or before_value is None). Takes into account emulation
        left_actual = super().resolve_used_value(left.before_value, instruction, left, emu)
        right_actual = super().resolve_used_value(right.before_value, instruction, right, emu)

        if left_actual is not None and right_actual is not None:
            print_left, print_right = pwndbg.enhance.format_small_int_pair(left_actual, right_actual)
            instruction.info_string = f"{print_left} {char_to_seperate_operands} {print_right}"

            if emu:
                eflags_bits = pwndbg.gdblib.regs.flags["eflags"]
                emu_eflags = emu.read_register("eflags")
                eflags_formatted = C.format_flags(emu_eflags, eflags_bits)

                SPACES = 5
                instruction.info_string += " "*SPACES + f"EFLAGS => {eflags_formatted}"

    def handle_cmp_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        self.handle_cmp_test_handler(instruction, emu, '-')

    def handle_test_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        self.handle_cmp_test_handler(instruction, emu, '&')

    def handle_xor_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        
        left, right = instruction.operands

        # If zeroing the register with XOR A, A. Can reason about this no matter where the instruction is
        if left.type == CS_OP_REG and right.type == CS_OP_REG and left.value.reg == right.value.reg:
            regname = C.register_changed(C.register(left.str.upper()))
            instruction.info_string = f"{regname} => 0"
        elif emu and left.after_value is not None:
            regname = C.register_changed(C.register(left.str.upper()))
            instruction.info_string = f"{regname} => {left.after_value}"

    def handle_inc_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        operand = instruction.operands[0]

        if operand.type == CS_OP_REG:
            if emu and operand.after_value is not None:
                regname = C.register_changed(C.register(operand.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get(operand.after_value)}"

    def handle_dec_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        self.handle_inc_set_info(instruction, emu)

    # Override
    def set_info_string(self, instruction: CsInsn, emu: Emulator) -> None:

        # TODO: Assume Intel syntax, flip operand order if AT&T

        # Dispatch to the correct handler
        self.set_info_string_handlers.get(instruction.id, lambda *a: None)(instruction, emu)
            

    # Read value at register
    def parse_register(self, instruction: CsInsn, operand: X86Op, emu: Emulator = None):
        reg = operand.value.reg
        # name = instruction.reg_name(reg)
        return self.read_register(instruction, reg, emu)

       
    # Read a register in the context of an instruction
    # Only return an integer if we can reason about the value, else None
    def read_register(self, instruction: CsInsn, operand_id: int, emu: Emulator):
        # operand_id is the ID internal to Capstone
        
        regname = instruction.reg_name(operand_id)

        if operand_id == X86_REG_RIP:
            # Ex: lea    rax, [rip + 0xd55] 
            # We can reason about this no matter the current pc
            return instruction.address + instruction.size
        else:
            if emu:
                # Will return the value of register after executing the instruction
                value = emu.read_register(regname)
                print(f"Register in emulation returned {regname}={hex(value)}")
                return value
            elif self.can_reason_about_process_state(instruction):        
                # When instruction address == pc, we can reason about all registers.
                # The values will just reflect values prior to executing the instruction, instead of after,
                # which is relevent if we are writing to this register.
                # However, the information can still be useful for display purposes.
                print(f"Live register value got: {pwndbg.gdblib.regs[regname]}")
                return pwndbg.gdblib.regs[regname]
            else:
                return None

    # Get memory address (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55. Does not dereference)
    def parse_memory(self, instruction: CsInsn, op: X86Op, emu: Emulator = None):
        
        target = 0

        # There doesn't appear to be a good way to read from segmented
        # addresses within GDB.
        if op.mem.segment != 0:
            return None

        if op.mem.base != 0:
            base = self.read_register(instruction, op.mem.base, emu)
            # read_register(instruction, op.mem.base)
            if base is None:
                return None
            target += base

        if op.mem.disp != 0:
            target += op.value.mem.disp

        if op.mem.index != 0:
            scale = op.mem.scale
            index = self.read_register(instruction, op.mem.index, emu)
            # index = self.read_register(instruction, op.mem.index)
            if index is None:
                return None

            target += scale * index

        return target


    def next(self, instruction, call=False):
        # Only enhance 'ret'
        if X86_INS_RET != instruction.id or len(instruction.operands) > 1:
            return super().next(instruction, call)

        # Stop disassembling at RET if we won't know where it goes to
        if instruction.address != pwndbg.gdblib.regs.pc:
            return None

        # Otherwise, resolve the return on the stack
        pop = 0
        if instruction.operands:
            pop = instruction.operands[0].before_value

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
        if efl is None:
            return False

        cf = efl & (1 << 0)
        pf = efl & (1 << 2)
        # af = efl & (1 << 4)
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

    def memory_string(self, instruction, op):
        arith = False
        segment = op.mem.segment
        disp = op.value.mem.disp
        base = op.value.mem.base
        index = op.value.mem.index
        scale = op.value.mem.scale
        sz = ""

        if segment != 0:
            sz += f"{instruction.reg_name(segment)}:"

        if base != 0:
            sz += instruction.reg_name(base)
            arith = True

        if index != 0:
            if arith:
                sz += " + "

            index = pwndbg.gdblib.regs[instruction.reg_name(index)]
            sz += f"{index}*{scale:#x}"
            arith = True

        if op.mem.disp != 0:
            if arith and op.mem.disp < 0:
                sz += " - "
            elif arith and op.mem.disp >= 0:
                sz += " + "
            sz += "%#x" % abs(op.mem.disp)

        sz = f"[{sz}]"
        return sz


assistant = DisassemblyAssistant("i386")
assistant = DisassemblyAssistant("x86-64")
