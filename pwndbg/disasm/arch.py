from __future__ import annotations

import gdb
from capstone import *  # noqa: F403
from typing import Callable

from pwndbg.emu.emulator import Emulator 
import pwndbg.gdblib.symbol
import pwndbg.lib.cache
import pwndbg.chain 

debug = False
# debug = True

groups = {v: k for k, v in globals().items() if k.startswith("CS_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("CS_OP_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

for value1, name1 in dict(access).items():
    for value2, name2 in dict(access).items():
        # novermin
        access.setdefault(value1 | value2, f"{name1} | {name2}")

# Enhances disassembly with memory values & symbols
#   The only public method that should be called is "enhance"
class DisassemblyAssistant:
    # Registry of all instances, {architecture: instance}
    assistants: Dict[str, DisassemblyAssistant] = {}

    def __init__(self, architecture: str) -> None:
        if architecture is not None:
            self.assistants[architecture] = self

        # Capstone doesn't expose a type for the "Operand" type, so "any"
        self.op_handlers: dict[int, Callable[[CsInsn, any, Emulator], int]]  = {
            CS_OP_IMM: self.parse_immediate,    # Return of immediate
            CS_OP_REG: self.parse_register,     # Return value of register
            # Handler for memory references (as dictated by Capstone), such as first operand of "mov qword ptr [rbx + rcx*4], rax"
            CS_OP_MEM: self.parse_memory,       # Return parsed address, do not dereference
        }

        self.op_names = {
            CS_OP_IMM: self.immediate_string,
            CS_OP_REG: self.register_string,
            CS_OP_MEM: self.memory_string,
        }

    @staticmethod
    def for_current_arch():
        return DisassemblyAssistant.assistants.get(pwndbg.gdblib.arch.current, None)

    # Mutates the "instruction" object
    @staticmethod
    def enhance(instruction: CsInsn, emu: Emulator = None) -> None:
        # Assumed that the emulator's just executed the instruction being enhanced

        print(f"Start enhancing instruction at {hex(instruction.address)} - {instruction.mnemonic} {instruction.op_str}")
        
        if emu:
            print(f"{hex(pwndbg.gdblib.regs.pc)=} {hex(emu.pc)=} and {hex(instruction.address)=} and {hex(instruction.size)}")
            
            # TODO: Not an assert
            assert(emu.last_pc == instruction.address)
            # else:
            #   emu = None

        enhancer: DisassemblyAssistant = DisassemblyAssistant.assistants.get(
            pwndbg.gdblib.arch.current, generic_assistant
        )

        enhancer.enhance_operands(instruction, emu)
        enhancer.enhance_conditional(instruction)
        enhancer.enhance_next(instruction)

        if debug:
            print(enhancer.dump(instruction))

        print(f"Done enhancing")

    # TODO: Write comment here
    def parse_operands(self, instruction, emu: Emulator) -> None:
        pass

    def enhance_operands(self, instruction: CsInsn, emu: Emulator = None) -> None:
        """
        Adds information regarding the execution of the instruction, such as operand values, symbols.

        This defines the "default" enhancement of operands - subclasses for specific architecture
        can implement their own logic (override this function), and fallback to this function.
        
        For each operation (instruction.operands), adds the following fields:

            operand.str:
                String of this operand, as it should appear in the disassembly.

            operand.int:
                Integer value of the operand, if it can be resolved, else None.

            operand.symbol:
                Resolved symbol name for this operand, if it can be resolved, else None


        We also add the `info_string` field to the instruction, which contains the string to
        be printed in a disasm view. It can include a symbol (<main+32>), or an address to print.
        Default is None.

        Examples info_string's:
            <main+32>
            [0x7fffffffdfb4] -> 0x2


        Also, in order for the display function to be able to replace any inline address in the operands
        with a symbol, we also add the `symbol` and `symbol_addr` fields.
        This is only set if, after parsing all of the operands, there is exactly one
        value which resolved to a named symbol, it will be set to
        that value. In all other cases, the value is `None`.

        Colors are not added to strings - this is done when actually printing 
        """
    
        # Default behavior:
        #  Enhance all operands explicitly written to or read from
        #  Set `info_string` to include the value of operand written to. Only one.
        #  Set the `symbol`, `symbol_addr` fields.

        instruction.info_string = None
        instruction.symbol = None

        for i, op in enumerate(instruction.operands):
            
            op.int = None
            op.symbol = None

            # Retrieve the value, either an immediate, from a register, or from memory
            op.int = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
            if op.int is not None:
                op.int &= pwndbg.gdblib.arch.ptrmask
                op.symbol = pwndbg.gdblib.symbol.get(op.int)

            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

            print(f"Operand #{i} = {op.str}")


        operands_with_write = [o for o in instruction.operands if o.int is not None and o.access & CS_AC_WRITE]
        operands_with_symbols = [o for o in instruction.operands if o.symbol]
        
        # If operand was written to
        if len(operands_with_write) == 1:
            print(f"Operand written {operands_with_write[0].reg} = {hex(operands_with_write[0].int)}")

            instruction.info_string = hex(operands_with_write[0].int)


        if len(operands_with_symbols) == 1:
            o = operands_with_symbols[0]

            instruction.symbol = o.symbol
            instruction.symbol_addr = o.int
            
            print(f"DEBUG: {o.symbol=}")

    # Get value at register.
    def parse_register(self, instruction: CsInsn, operand, emu: Emulator = None):
        
        # If we are about to run this instruction, we can read all registers safely (haven't been mutated by in-between instructions)
        # if pwngdb.arch.reg.pc == instruction.address

        reg = operand.value.reg
        name = instruction.reg_name(reg)

        return self.read_register(instruction, name, emu)
    

    def read_register(self, instruction: CsInsn, regname: str, emu: Emulator) -> int:

        print(f"Attempting to get register value `{regname}`")

        if emu:
            # Will return the value of register after executing the instruction
            value = emu.read_register(regname)
            print(f"Register in emulation returned {regname}={hex(value)}")
            return value
        elif instruction.address == pwndbg.gdblib.regs.pc:
            # We can reason about all registers if not emulating, 
            # the values will just reflect values prior to executing the instruction, and not after,
            # which is relevent if we are writing to this register.
            # However, the information can still be useful for display purposes.
            print(f"Live register value got: {pwndbg.gdblib.regs[regname]}")
            return pwndbg.gdblib.regs[regname]
        else:
            return None

            # TODO: Get rid of old comment
            # # Don't care about registers which are only overwritten
            # if operand.access & CS_AC_WRITE and not operand.access & CS_AC_READ:
            #     return None
    
    # Subclasses override
    # Get memory address of operand (Ex: lea    rax, [rip + 0xd55], this would return $rip+0xd55)
    def parse_memory(self, instruction: CsInsn, operand, emu: Emulator = None):
        return None
    
    def parse_immediate(self, instruction, operand, emu: Emulator = None):
        return operand.value.imm
    
    # Dereference an address recursively - takes into account emulation, returns None if cannot reason about the address
    def telescope(self, address: int, limit: int, instruction, operand, emu: Emulator) -> int | None:
        
        pc_is_at_instruction = instruction.address == pwndbg.gdblib.regs.pc
        
        # We can read from memory. Note that if the instruction is writing to this address,
        # the value will likely be out of date without emulation
        if pc_is_at_instruction and not (operand.access & CS_AC_WRITE):
            return pwndbg.chain.get(address, limit=limit)
        elif emu:
            return emu.telescope(address, limit)
        
        return None


    # Assumes operand.int has already been set
    def immediate_string(self, instruction, operand) -> str:
        value = operand.int

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    def register_string(self, instruction, operand):
        reg = operand.value.reg
        return instruction.reg_name(reg).lower()

    # Subclasses may override
    def memory_string(self, instruction, operand):
        return None  # raise NotImplementedError

    def enhance_conditional(self, instruction: CsInsn) -> None:
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

    def condition(self, instruction) -> bool:
        return False

    def enhance_next(self, instruction: CsInsn) -> None:
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

    def next(self, instruction: CsInsn, call=False):
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
                addr = self.parse_memory(instruction, op)

            # self.memory may return none, so we need to check it here again
            if addr is not None:
                try:
                    # fails with gdb.MemoryError if the dereferenced address
                    # doesn't belong to any of process memory maps
                    addr = int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, addr))
                except gdb.MemoryError:
                    return None
        if op.type == CS_OP_REG:
            addr = self.parse_register(instruction, op)

        # Evidently this can happen?
        if addr is None:
            return None

        return int(addr)

    def dump(self, instruction):
        """
        Debug-only method.
        """
        ins = instruction
        rv = []
        rv.append(f"{ins.mnemonic} {ins.op_str}")

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
                rv.append(f"            sym = {(op.symbol)}")
            if op.str is not None:
                rv.append(f"            str = {(op.str)}")

        return "\n".join(rv)


generic_assistant = DisassemblyAssistant(None)
