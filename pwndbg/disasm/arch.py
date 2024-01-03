from __future__ import annotations

import gdb
from capstone import *  # noqa: F403
from typing import Callable
from pwndbg.emu.emulator import Emulator 
import pwndbg.gdblib.symbol
import pwndbg.gdblib.memory
import pwndbg.gdblib.typeinfo
# import pwndbg.gdblib.config
import pwndbg.lib.cache
import pwndbg.chain 


pwndbg.gdblib.config.add_param(
    "emulate-annotations",
    True,
    """
Unicorn emulation for register and memory value annotations on instructions
"""
)

# If this is false, emulation is only used for the current instruction (if emulate-annotations is enabled)
pwndbg.gdblib.config.add_param(
    "emulate-future-annotations",
    True,
    """
Unicorn emulation to annotate instructions after the current program counter
"""
)

pwndbg.gdblib.config.add_param(
    "disasm-telescope-depth",
    3,
    "Depth of telescope for disasm annotations"
)

# In disasm view, long telescoped strings might cause lines wraps
pwndbg.gdblib.config.add_param(
    "disasm-telescope-string-length",
    50,
    "Number of characters in strings to display in disasm annotations"
)



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
# by adding member variables to an instruction
# The only public method that should be called is "enhance"
# The enhance function is passed an instance of the Unicorn emulator
#  and will .single_step() it to determine operand values before and after executing the instruction
class DisassemblyAssistant:
    # Registry of all instances, {architecture: instance}
    assistants: Dict[str, DisassemblyAssistant] = {}

    def __init__(self, architecture: str) -> None:
        if architecture is not None:
            self.assistants[architecture] = self

        # The Capstone type for the "Operand" depends on the Arch
        # Types found in capstone.ARCH_NAME.py, such as capstone.x86.py
        self.op_handlers: dict[int, Callable[[CsInsn, object, Emulator], int]]  = {
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
        # Assumed that the emulator's pc is at the instructions address

        print(f"Start enhancing instruction at {hex(instruction.address)} - {instruction.mnemonic} {instruction.op_str}")
        
        # For both cases below, we still step the emulation so we can use it to determine jump target
        # in the pwndbg.disasm.near() function.
        if emu and not bool(pwndbg.gdblib.config.emulate_annotations):
            emu.single_step(check_instruction_valid=False)
            emu = None

        # If we are not at the current process instruction, and we don't want to emulate future annotations, we
        # make emu None.
        print(pwndbg.gdblib.config.emulate_future_annotations)
        if emu and pwndbg.gdblib.regs.pc != instruction.address and not bool(pwndbg.gdblib.config.emulate_future_annotations):
            emu.single_step(check_instruction_valid=False)
            emu = None

        if emu:
            # print(f"{hex(pwndbg.gdblib.regs.pc)=} {hex(emu.pc)=} and {hex(instruction.address)=}")
            
            assert(emu.pc == instruction.address)

            # if emu.pc != instruction.address:
            #   print("This indicates a bug in Pwndbg, please report")
            #   emu = None

        enhancer: DisassemblyAssistant = DisassemblyAssistant.assistants.get(
            pwndbg.gdblib.arch.current, generic_assistant
        )

        enhancer.enhance_operands(instruction, emu)
        enhancer.enhance_conditional(instruction)
        enhancer.enhance_next(instruction)

        instruction.info_string = None
        enhancer.set_info_string(instruction, emu)

        if debug:
            print(enhancer.dump(instruction))

        print(f"Done enhancing")


    # Subclasses for specific architecture should override this
    def set_info_string(self, instruction: CsInsn, emu: Emulator) -> None:
        """
        The goal of this function is to add the `info_string` field to the instruction, which is the string to
        be printed in a disasm view.
        """
        return None

    def enhance_operands(self, instruction: CsInsn, emu: Emulator = None) -> None:
        """
        Adds information regarding the execution of the instruction, such as operand values, symbols.

        When emulation is enabled, this will `single_step` the emulation to determine the value of registers
        before and after the instrution has executed.
        
        For each operand explicitly written to or read from (instruction.operands), adds the following fields:

            operand.before_value
                Integer value of the operand before instruction executes. 
                None if cannot be resolved/reasoned about.

            operand.after_value
                Integer value of the operand after instruction executes.
                Only set when emulation is enabled. Otherwise None.
                This is relevent if we read and write to the same registers within an instruction

            operand.symbol:
                Resolved symbol name for this operand, if .before_value is set, else None.

            operand.str:
                String of this operand, as it should appear in the disassembly.
                # TODO: Currently not used

        Also, in order for the display function to be able to replace any inline address in the operands
        with a symbol, we add the `symbol` and `symbol_addr` fields.
        This is only set if, after parsing all of the operands, there is exactly one
        value which resolved to a named symbol, it will be set to
        that value. In all other cases, the value is `None`.
        """

        # For ease, for x86 we will assume Intel syntax (destination operand first).
        # However, Capstone will disassemble using the `set disassembly-flavor` preference,
        # and the order of operands are read left to right into the .operands array. So we flip operand order if AT&T

        if instruction._cs.syntax == CS_OPT_SYNTAX_ATT:
            instruction.operands.reverse()


        # before_value
        for i, op in enumerate(instruction.operands):
            
            op.symbol = None

            # Retrieve the value, either an immediate, from a register, or from memory
            op.before_value = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
            if op.before_value is not None:
                op.before_value &= pwndbg.gdblib.arch.ptrmask
                op.symbol = pwndbg.gdblib.symbol.get(op.before_value)

            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

            print(f"Before operand #{i} = {op.str}, {op.size=}")


        # Execute the instruction and set after_value
        if emu and None not in emu.single_step(check_instruction_valid=False):
            # after_value
            for i, op in enumerate(instruction.operands):
                
                # Retrieve the value, either an immediate, from a register, or from memory
                op.after_value = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
                if op.after_value is not None:
                    op.after_value &= pwndbg.gdblib.arch.ptrmask

                print(f"After operand #{i} = {op.after_value:x}")
        else:
            # If it failed, set to None so we don't accidentally try to get info from it 
            emu = None
            for op in instruction.operands:
                op.after_value = None


        instruction.symbol = None

        operands_with_symbols = [o for o in instruction.operands if o.symbol]
        
        if len(operands_with_symbols) == 1:
            o = operands_with_symbols[0]

            instruction.symbol = o.symbol
            instruction.symbol_addr = o.before_value
            
            print(f"DEBUG: {o.symbol=}")

    # Determine if the program counter of the process equals the address of the function being executed. 
    # If so, it means we can safely reason and read from registers and memory to represent values that 
    # we can add to the .info_string. This becomes relevent when NOT emulating, and is meant to 
    # allow more details when the PC is at the instruction being enhanced
    def can_reason_about_process_state(self, instruction: CsInsn) -> bool:
        return instruction.address == pwndbg.gdblib.regs.pc

    # Read value in register
    # Different architectures use registers in different patterns, so it is best to
    # override this to get to best behavior for a given architecture.
    def parse_register(self, instruction: CsInsn, operand, emu: Emulator = None):
        if not self.can_reason_about_process_state(instruction):
            return None

        reg = operand.value.reg
        name = instruction.reg_name(reg)
        return pwndbg.gdblib.regs[name]
    
    # Get memory address of operand (Ex: in x86, mov rax, [rip + 0xd55], would return $rip_after_instruction+0xd55)
    # Subclasses override
    def parse_memory(self, instruction: CsInsn, operand, emu: Emulator = None):
        return None
    
    def parse_immediate(self, instruction, operand, emu: Emulator = None):
        return operand.value.imm
    
    # Dereference an address recursively - takes into account emulation. 
    # If cannot dereference safely, returns a list with just the passed in address.
    # Note that this means the last value might be a pointer, while the format functions expect
    # to receive a list of deferenced pointers with the last value being a non-pointer
    # This is why we return a Tuple[list[int], did_telescope: boolean]
    #   The first value is the list of addresses, the second is a boolean to indicate if telescoping occured,
    #   or if the address was just sent back as the only value in a list.
    #   This is important for the formatting function, as we pass the boolean there to indicate if during
    #   enhancement of the last value in the chain we should attempt to dereference it or not.
    #   We shouldn't dereference during enhancement if we cannot reason about the value in memory
    #
    # The list that the function returns is guaranteed have len >= 1 
    def telescope(self, address: int, limit: int, instruction: CsInsn, operand, emu: Emulator, read_size:int=None) -> tuple[list[int], bool]:
        # It is assumed proper checks have been made BEFORE calling this function so that `address`
        # is not None, and so that in the case of non-emulation, pwndbg.chain.format will return values 
        # accurate to the program state after the instruction has executed. If just using operand values,
        # this should work automatically, as `enhance_operands` only sets values it can reason about.
        #
        # can_read_process_state indicates if the current program counter of the process is the same as the instruction
        # The way to determine this varies between architectures (some arches have PC a constant offset to instruction address), 
        # so subclasses need to specify

        can_read_process_state = self.can_reason_about_process_state(instruction)

        if emu:
            return (emu.telescope(address, limit, read_size=read_size), True)
        elif can_read_process_state:
            # Can reason about memory in this case. 

            if read_size is not None and read_size != pwndbg.gdblib.arch.ptrsize:
                result = [address]

                size_type = pwndbg.gdblib.typeinfo.get_type(read_size)
                try:
                    read_value = pwndbg.gdblib.memory.poi(size_type, address)
                    result.append(read_value)
                except gdb.MemoryError:
                    pass

                return (result, True)
                
            else:
                return (pwndbg.chain.get(address, limit=limit), True)
        elif not can_read_process_state or operand.type == CS_OP_IMM:
            # If the target address is in a non-writeable map, we can pretty safely telescope
            # This is best-effort to give a better experience
            page = pwndbg.gdblib.vmmap.find(address)
            print(page, f"{address:x}")
            if page and not page.write:
                return (pwndbg.chain.get(address, limit=limit), True)
        
        # We cannot telescope, but we can still return the address.
        # Just without any further information
        return ([address], False)

    # Read memory of given size, taking into account emulation and being able to reason about the memory location
    def read_memory(self, address: int, size: int, instruction: CsInsn, operand, emu: Emulator) -> int | None:
        address_list, did_telescope = self.telescope(address, 1, instruction, operand, emu, read_size=size)
        if did_telescope:
            if len(address_list) >= 2:
                return address_list[1]
        return None

    # Dispatch to the appropriate format handler. Pass the list returned by `telescope()` to this function
    def telescope_format_list(self, list: list[int], limit: int, emu: Emulator, enhance_can_dereference: bool) -> str:
        # It is assumed proper checks have been made BEFORE calling this function so that pwndbg.chain.format 
        #  will return values accurate to the program state at the time of instruction executing.
        #  For some cases, it's best to assume the string will stay constant, like global string variables

        enhance_string_len = int(pwndbg.gdblib.config.disasm_telescope_string_length)

        if emu:
            return emu.format_telescope_list(list, limit, enhance_string_len=enhance_string_len)
        else:
            # We can format, but in some cases we may not be able to reason about memory, so don't allow 
            # it to dereference to last value in memory (we can't determine what value it is)
            return pwndbg.chain.format(list, limit=limit, enhance_can_dereference=enhance_can_dereference, enhance_string_len=enhance_string_len)

    # Pass in a operand and it's value, and determine the actual value used during an instruction
    # Helpful for cases like  `cmp    byte ptr [rip + 0x166669], 0`, where first operand could be
    # a register or a memory value to dereference, and we want the actual value used.
    # Return None if cannot dereference in the case it's a memory address
    def resolve_used_value(self, value: int | None, instruction: CsInsn, operand, emu: Emulator) -> int | None:
        if value is None:
            return None
        
        if operand.type == CS_OP_REG or operand.type == CS_OP_IMM:
            return value
        elif operand.type == CS_OP_MEM:
            print(operand.size)
            return self.read_memory(value, operand.size, instruction, operand, emu)
    


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

        if instruction.operands and instruction.operands[0].before_value:
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

        op = instruction.operands[0]
        addr = op.before_value
        if addr:
            addr &= pwndbg.gdblib.arch.ptrmask
        if op.type == CS_OP_MEM:
            if addr is None:
                addr = self.parse_memory(instruction, op, None)

            # self.parse_memory may return none, so we need to check it here again
            if addr is not None:
                try:
                    # fails with gdb.MemoryError if the dereferenced address
                    # doesn't belong to any of process memory maps
                    addr = int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.ppvoid, addr))
                except gdb.MemoryError:
                    return None
        if op.type == CS_OP_REG:
            addr = self.parse_register(instruction, op, None)

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

            if op.before_value is not None:
                rv.append("            int = %#x" % (op.before_value))
            if op.symbol is not None:
                rv.append(f"            sym = {(op.symbol)}")
            if op.str is not None:
                rv.append(f"            str = {(op.str)}")

        return "\n".join(rv)



    def immediate_string(self, instruction, operand) -> str:
        value = operand.before_value

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    def register_string(self, instruction, operand):
        reg = operand.value.reg
        return instruction.reg_name(reg).lower()

    # Subclasses may override
    def memory_string(self, instruction, operand):
        return None  # raise NotImplementedError

generic_assistant = DisassemblyAssistant(None)
