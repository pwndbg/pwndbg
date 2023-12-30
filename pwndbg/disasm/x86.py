from __future__ import annotations
from typing import Callable

from capstone import *  # noqa: F403
from capstone.x86 import *  # noqa: F403

from pwndbg.emu.emulator import Emulator 
import pwndbg.color.context as C
import pwndbg.color.memory as MemoryColor
import pwndbg.chain

import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.gdblib.typeinfo

groups = {v: k for k, v in globals().items() if k.startswith("X86_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("X86_OP_")}
regs = {v: k for k, v in globals().items() if k.startswith("X86_REG_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

pc = X86_REG_RSP

# TODO: Make this more complete
# MOV_INSTRUCTIONS = {
#     X86_INS_MOV,
#     X86_INS_MOVABS,
#     X86_INS_MOVZX,

#     X86_INS_MOVD,
#     X86_INS_MOVQ,
# }

TELESCOPE_DEPTH = 2

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

            # XOR
            X86_INS_XOR: self.handle_xor_set_info,

            # INC and DEC
            X86_INS_INC: self.handle_inc_set_info,
            X86_INS_DEC: self.handle_dec_set_info,
            
        }


    def handle_mov_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        if len(instruction.operands) == 2:
            left, right = instruction.operands
            if left.int is not None and right.int is not None:
                

                telescope_addresses = super().telescope(right.int, TELESCOPE_DEPTH, instruction, right, emu)
                # This can return a singleton list. Don't assume it won't 

                # TODO: DELETE THIS
                to_print = pwndbg.chain.format(right.int, limit=0)

                
                ##########
                ##########
                # .format is broken!
                # TODO: Create custom format that reads from IN memory
                # Also, fix the outside .format, because it just breaks
                print("1")
                print(f"{telescope_addresses}")
                print(f"{pwndbg.chain.format(telescope_addresses)}")
                print(f"{pwndbg.chain.format([*telescope_addresses, 1])}")
                
                print("Raw format")
                print(f"{to_print}")

                print("Second to last")
                print(f"{pwndbg.chain.get(right.int, limit=0)}")
                
                print("Last")
                print(f"{pwndbg.chain.format(pwndbg.chain.get(right.int, limit=0))}")


                if left.type == CS_OP_MEM: # right.type must then be either CS_OP_REG or CS_OP_IMM. Cannot MOV mem to mem
                    

                    if telescope_addresses:
                        # instruction.info_string = f"[{MemoryColor.get(left.int)}] => {to_print=}"

                        instruction.info_string = f"[{MemoryColor.get(left.int)}] => {pwndbg.chain.format(telescope_addresses)}"
                
                elif left.type == CS_OP_REG and right.type in (CS_OP_REG, CS_OP_IMM):

                    if telescope_addresses:
                        regname = C.register_changed(C.register(left.str.upper()))
                        # instruction.info_string = f"{regname} => {to_print}"

                        instruction.info_string = f"{regname} => {pwndbg.chain.format(telescope_addresses)}"
                
                elif left.type == CS_OP_REG and right.type == CS_OP_MEM:

                    if telescope_addresses:
                        regname = C.register_changed(C.register(left.str.upper()))
                        # Start showing at dereferenced by, hence the [1:]
                        instruction.info_string = f"{regname}/[{MemoryColor.get(right.int)}] => {pwndbg.chain.format(telescope_addresses[1:])}"

    def handle_lea_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        # Example: lea    rdx, [rax*8]
        left, right = instruction.operands
        if left.int is not None and right.int is not None:
            regname = C.register_changed(C.register(left.str.upper()))
            instruction.info_string = f"{regname} => {MemoryColor.get(right.int)}"

    def handle_pop_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        pc_is_at_instruction = instruction.address == pwndbg.gdblib.regs.pc

        reg_operand = instruction.operands[0]

        # It is possible to pop [0xdeadbeef] and pop dword [esp]
        if reg_operand.type == CS_OP_REG:
            if emu:
                # After emulation, the register has taken on the popped value
                regname = C.register_changed(C.register(reg_operand.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get(reg_operand.int)}"
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

        if emu:
            if left.type == CS_OP_REG and (right.type == CS_OP_REG or right.type == CS_OP_IMM):
                # RAX = 5, RBX = 3
                regname = C.register_changed(C.register(left.str.upper()))
                # TODO: Maybe telescope this? But keep it constrained to interesting types, things with symbols or strings
                instruction.info_string = f"{regname} => {MemoryColor.get(left.int)}"

    def handle_sub_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        left, right = instruction.operands
            
        if emu:
            if left.type == CS_OP_REG and (right.type == CS_OP_REG or right.type == CS_OP_IMM):
                regname = C.register_changed(C.register(left.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get(left.int)}"
        
    def handle_cmp_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        pc_is_at_instruction = instruction.address == pwndbg.gdblib.regs.pc
        
        left, right = instruction.operands

        if pc_is_at_instruction or emu:
            if left.type == CS_OP_REG and (right.type == CS_OP_REG or right.type == CS_OP_IMM):
                instruction.info_string = f"{left.int} - {right.int}"

    def handle_xor_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        pc_is_at_instruction = instruction.address == pwndbg.gdblib.regs.pc
        
        left, right = instruction.operands

        # If zeroing the register with XOR A, A. Can reason about this no matter where the instruction is
        if left.type == CS_OP_REG and right.type == CS_OP_REG and left.value.reg == right.value.reg:
            regname = C.register_changed(C.register(left.str.upper()))
            instruction.info_string = f"{regname} => 0"
        elif emu:
            regname = C.register_changed(C.register(left.str.upper()))
            instruction.info_string = f"{regname} => {left.int}"

    def handle_inc_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        operand = instruction.operands[0]

        if operand.type == CS_OP_REG:
            if emu:
                regname = C.register_changed(C.register(operand.str.upper()))
                instruction.info_string = f"{regname} => {MemoryColor.get(operand.int)}"

    def handle_dec_set_info(self, instruction: CsInsn, emu: Emulator) -> None:
        self.handle_inc_set_info(instruction, emu)
                

    # Overload
    def set_info_string(self, instruction: CsInsn, emu: Emulator) -> None:

        # TODO: Assume Intel syntax, flip operand order if AT&T

        # Dispatch to the correct handler
        self.set_info_string_handlers.get(instruction.id, lambda *a: None)(instruction, emu)
            

    # Read value at register
    def parse_register(self, instruction: CsInsn, operand, emu: Emulator):
        reg = operand.value.reg
        # name = instruction.reg_name(reg)
        return self.read_register(instruction, reg, emu)

       
    # Read a register in the context of an instruction
    # operand_id is the ID internal to Capstone
    def read_register(self, instruction: CsInsn, operand_id: int, emu: Emulator):
        
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
            elif instruction.address == pwndbg.gdblib.regs.pc:        
                # When instruction address == pc, we can reason about all registers.
                # The values will just reflect values prior to executing the instruction, instead of after,
                # which is relevent if we are writing to this register.
                # However, the information can still be useful for display purposes.
                print(f"Live register value got: {pwndbg.gdblib.regs[regname]}")
                return pwndbg.gdblib.regs[regname]
            else:
                return None

    # Get memory address (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55. Does not dereference)
    def parse_memory(self, instruction: CsInsn, op, emu: Emulator = None):
        
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
            pop = instruction.operands[0].int

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
        af = efl & (1 << 4)
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
