from __future__ import annotations

from typing import Callable

import gdb
from capstone import *  # noqa: F403

import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.color.syntax_highlight as H
import pwndbg.color.memory as MemoryColor
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.gdblib.vmmap
from pwndbg.disasm.instruction import EnhancedOperand
from pwndbg.disasm.instruction import InstructionCondition
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

# Even if this is disabled, branch instructions will still have targets printed
pwndbg.gdblib.config.add_param(
    "disasm-annotations",
    True,
    """
Display annotations for instructions to provide context on operands and results
""",
)

pwndbg.gdblib.config.add_param(
    "emulate-annotations",
    True,
    """
Unicorn emulation for register and memory value annotations on instructions
""",
)

# If this is false, emulation is only used for the current instruction (if emulate-annotations is enabled)
pwndbg.gdblib.config.add_param(
    "emulate-future-annotations",
    True,
    """
Unicorn emulation to annotate instructions after the current program counter
""",
)

# Effects future instructions, as past ones have already been cached and reflect the process state at the time
pwndbg.gdblib.config.add_param(
    "disasm-telescope-depth", 3, "Depth of telescope for disasm annotations"
)

# In disasm view, long telescoped strings might cause lines wraps
pwndbg.gdblib.config.add_param(
    "disasm-telescope-string-length",
    50,
    "Number of characters in strings to display in disasm annotations",
)


def syntax_highlight(ins):
    return H.syntax_highlight(ins, filename=".asm")


DEBUG_ENHANCEMENT = False
# DEBUG_ENHANCEMENT = True

groups = {v: k for k, v in globals().items() if k.startswith("CS_GRP_")}
ops = {v: k for k, v in globals().items() if k.startswith("CS_OP_")}
access = {v: k for k, v in globals().items() if k.startswith("CS_AC_")}

for value1, name1 in dict(access).items():
    for value2, name2 in dict(access).items():
        # novermin
        access.setdefault(value1 | value2, f"{name1} | {name2}")

# These instruction types should not be emulated through, either
# because they cannot be emulated without interfering (syscall, etc.)
# or because they may take a long time (call, etc.), or because they
# change privilege levels.
DO_NOT_EMULATE = {
    CS_GRP_INT,
    CS_GRP_INVALID,
    CS_GRP_IRET,
    # Note that we explicitly do not include the PRIVILEGE category, since
    # we may be in kernel code, and privileged instructions are just fine
    # in that case.
    # capstone.CS_GRP_PRIVILEGE,
}


# Enhances disassembly with memory values & symbols by adding member variables to an instruction
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
        self.op_handlers: dict[
            int, Callable[[PwndbgInstruction, EnhancedOperand, Emulator], int | None]
        ] = {
            CS_OP_IMM: self.parse_immediate,  # Return immediate value
            CS_OP_REG: self.parse_register,  # Return value of register
            # Handler for memory references (as dictated by Capstone), such as first operand of "mov qword ptr [rbx + rcx*4], rax"
            CS_OP_MEM: self.parse_memory,  # Return parsed address, do not dereference
        }

        # Return a string corresponding to operand. Used to reduce code duplication while printing
        # REG type wil return register name, "RAX"
        self.op_names: dict[int, Callable[[PwndbgInstruction, EnhancedOperand], str | None]] = {
            CS_OP_IMM: self.immediate_string,
            CS_OP_REG: self.register_string,
            CS_OP_MEM: self.memory_string,
        }

    @staticmethod
    def for_current_arch() -> DisassemblyAssistant:
        return DisassemblyAssistant.assistants.get(pwndbg.gdblib.arch.current, None)

    # Mutates the "instruction" object
    @staticmethod
    def enhance(instruction: PwndbgInstruction, emu: Emulator = None) -> None:
        # Assumed that the emulator's pc is at the instruction's address

        if DEBUG_ENHANCEMENT:
            print(
                f"Start enhancing instruction at {hex(instruction.address)} - {instruction.mnemonic} {instruction.op_str}"
            )

        # For both cases below, we still step the emulation so we can use it to determine jump target
        # in the pwndbg.disasm.near() function. Then, set emu to None so we don't use it for annotation
        if emu and not bool(pwndbg.gdblib.config.emulate_annotations):
            emu.single_step(check_instruction_valid=False)
            emu = None

        # Disable emulation for future annotations based on setting
        if (
            emu
            and pwndbg.gdblib.regs.pc != instruction.address
            and not bool(pwndbg.gdblib.config.emulate_future_annotations)
        ):
            emu.single_step(check_instruction_valid=False)
            emu = None

        # Ensure emulator's program counter is at the correct location.
        # This occurs very rarely - observed sometimes when the remote is stalling, ctrl-c, and for some reason emulator returns PC=0.
        if emu:
            if emu.pc != instruction.address:
                if DEBUG_ENHANCEMENT:
                    print(
                        f"Program counter and emu.pc do not line up: {hex(pwndbg.gdblib.regs.pc)=} {hex(emu.pc)=}"
                    )
                emu = None

        # Disable emulation for instructions we don't want to emulate (CALL, INT, ...)
        if emu and set(instruction.groups) & DO_NOT_EMULATE:
            emu.valid = False
            emu = None

            if DEBUG_ENHANCEMENT:
                print("Turned off emulation - not emulating certain type of instruction")

        enhancer: DisassemblyAssistant = DisassemblyAssistant.assistants.get(
            pwndbg.gdblib.arch.current, generic_assistant
        )

        # This function will .single_step the emulation
        if not enhancer.enhance_operands(instruction, emu):
            if emu is not None and DEBUG_ENHANCEMENT:
                print(f"Emulation failed at {instruction.address=:#x}")
            emu = None

        if emu is not None:
            # We successfully used emulation for this instruction
            instruction.emulated = True

        # Set the .condition field
        enhancer.enhance_conditional(instruction, emu)

        # Set the .target and .next fields
        enhancer.enhance_next(instruction, emu)

        if bool(pwndbg.gdblib.config.disasm_annotations):
            enhancer.set_annotation_string(instruction, emu)

        # Disable emulation after CALL instructions. We do it after enhancement, as we can use emulation
        # to determine the call's target address.
        if emu and CS_GRP_CALL in set(instruction.groups):
            emu.valid = False
            emu = None

            if DEBUG_ENHANCEMENT:
                print("Turned off emulation for call")

        if DEBUG_ENHANCEMENT:
            print(enhancer.dump(instruction))
            print("Done enhancing")

    # Subclasses for specific architecture should override this
    def set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        The goal of this function is to set the `annotation` field of the instruction,
        which is the string to be printed in a disasm view.
        """
        return None

    def enhance_operands(self, instruction: PwndbgInstruction, emu: Emulator) -> bool:
        """
        Enhances the operands by determining values and symbols

        When emulation is enabled, this will `single_step` the emulation to determine the value of registers
        before and after the instrution has executed.

        For each operand explicitly written to or read from (instruction.operands), sets the following fields:

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
                String representing the operand

        Return False if emulation fails (so we don't use it in additional enhancement steps)
        """

        # Apply syntax highlighting to the assembly
        if pwndbg.gdblib.config.syntax_highlight:
            instruction.asm_string = syntax_highlight(instruction.asm_string)

        # Populate the "operands" list of the instruction
        # Set before_value, symbol, and str
        for op in instruction.operands:
            # Retrieve the value, either an immediate, from a register, or from memory
            op.before_value = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
            if op.before_value is not None:
                op.before_value &= pwndbg.gdblib.arch.ptrmask
                op.symbol = MemoryColor.attempt_colorized_symbol(op.before_value)

                if op.symbol and op.type == CS_OP_IMM:
                    # Make an inline replacement, so `jump 0x400122` becomes `jump function_name`
                    instruction.asm_string = instruction.asm_string.replace(hex(op.before_value), op.symbol)


        # Execute the instruction and set after_value
        if emu and None not in emu.single_step(check_instruction_valid=False):
            # after_value
            for op in instruction.operands:
                # Retrieve the value, either an immediate, from a register, or from memory
                op.after_value = self.op_handlers.get(op.type, lambda *a: None)(
                    instruction, op, emu
                )
                if op.after_value is not None:
                    op.after_value &= pwndbg.gdblib.arch.ptrmask
        else:
            emu = None

        # Set .str value of operands, after emulation has been completed
        for op in instruction.operands:
            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

        return emu is not None

    # Determine if the program counter of the process equals the address of the function being executed.
    # If so, it means we can safely reason and read from registers and memory to represent values that
    # we can add to the .info_string. This becomes relevent when NOT emulating, and is meant to
    # allow more details when the PC is at the instruction being enhanced
    def can_reason_about_process_state(self, instruction: PwndbgInstruction) -> bool:
        return instruction.address == pwndbg.gdblib.regs.pc

    # Delegates to "read_register", which takes Capstone ID for register.
    def parse_register(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        reg = operand.reg
        return self.read_register(instruction, reg, emu)

    # Determine memory address of operand (Ex: in x86, mov rax, [rip + 0xd55], would return $rip_after_instruction+0xd55)
    # Subclasses override for specific architectures
    def parse_memory(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        return None

    def parse_immediate(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ):
        return operand.imm

    # Read value in register. Return None if cannot reason about the value in the register.
    # Different architectures use registers in different patterns, so it is best to
    # override this to get to best behavior for a given architecture. See x86.py as example.
    def read_register(
        self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator
    ) -> int | None:
        # operand_id is the ID internal to Capstone
        regname: str = instruction.cs_insn.reg_name(operand_id)

        if emu:
            # Will return the value of register after executing the instruction
            value = emu.read_register(regname)
            if DEBUG_ENHANCEMENT:
                print(f"Register in emulation returned {regname}={hex(value)}")
            return value
        elif self.can_reason_about_process_state(instruction):
            # When instruction address == pc, we can reason about all registers.
            # The values will just reflect values prior to executing the instruction, instead of after,
            # which is relevent if we are writing to this register.
            # However, the information can still be useful for display purposes.
            if DEBUG_ENHANCEMENT:
                print(f"Read value from process register: {pwndbg.gdblib.regs[regname]}")
            return pwndbg.gdblib.regs[regname]
        else:
            return None

    # Read memory of given size, taking into account emulation and being able to reason about the memory location
    def read_memory(
        self,
        address: int,
        size: int,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
    ) -> int | None:
        address_list, did_telescope = self.telescope(
            address, 1, instruction, operand, emu, read_size=size
        )
        if did_telescope:
            if len(address_list) >= 2:
                return address_list[1]
        return None

    # Pass in a operand and it's value, and determine the actual value used during an instruction
    # Helpful for cases like  `cmp    byte ptr [rip + 0x166669], 0`, where first operand could be
    # a register or a memory value to dereference, and we want the actual value used.
    # Override this to implement memory lookups in given architecture (if it's relevent)
    # Different architecture read memory differently:
    # - Only a couple Capstone architectures support the memory .size field, which determines read width.
    # - In others, read/write width is implied.
    def resolve_used_value(
        self,
        value: int | None,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
    ) -> int | None:
        if value is None:
            return None

        if operand.type == CS_OP_REG or operand.type == CS_OP_IMM:
            return value
        elif operand.type == CS_OP_MEM:
            # Assume that we are reading ptrsize - subclasses should override this function
            # to provide a more specific value if needed
            self.read_memory(value, pwndbg.gdblib.arch.ptrsize, instruction, operand, emu)

        return None

    # Dereference an address recursively - takes into account emulation.
    # If cannot dereference safely, returns a list with just the passed in address.
    # Note that this means the last value might be a pointer, while the format functions expect
    # to receive a list of deferenced pointers with the last value being a non-pointer
    #
    # This is why we return a Tuple[list[int], did_telescope: boolean]
    #   The first value is the list of addresses, the second is a boolean to indicate if telescoping occured,
    #   or if the address was just sent back as the only value in a list.
    #   This is important for the formatting function, as we pass the boolean there to indicate if during
    #   enhancement of the last value in the chain we should attempt to dereference it or not.
    #   We shouldn't dereference during enhancement if we cannot reason about the value in memory
    #
    # The list that the function returns is guaranteed have len >= 1
    def telescope(
        self,
        address: int,
        limit: int,
        instruction: PwndbgInstruction,
        operand: EnhancedOperand,
        emu: Emulator,
        read_size: int = None,
    ) -> tuple[list[int], bool]:
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
                    read_value = int(pwndbg.gdblib.memory.poi(size_type, address))
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
            if page and not page.write:
                return (pwndbg.chain.get(address, limit=limit), True)

        # We cannot telescope, but we can still return the address.
        # Just without any further information
        return ([address], False)

    # Dispatch to the appropriate format handler. Pass the list returned by `telescope()` to this function
    def telescope_format_list(
        self, addresses: list[int], limit: int, emu: Emulator, enhance_can_dereference: bool
    ) -> str:
        # It is assumed proper checks have been made BEFORE calling this function so that pwndbg.chain.format
        #  will return values accurate to the program state at the time of instruction executing.

        enhance_string_len = int(pwndbg.gdblib.config.disasm_telescope_string_length)

        if emu:
            return emu.format_telescope_list(
                addresses, limit, enhance_string_len=enhance_string_len
            )
        else:
            # We can format, but in some cases we may not be able to reason about memory, so don't allow
            # it to dereference to last value in memory (we can't determine what value it is)
            return pwndbg.chain.format(
                addresses,
                limit=limit,
                enhance_can_dereference=enhance_can_dereference,
                enhance_string_len=enhance_string_len,
            )

    def enhance_conditional(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        Sets the `condition` of the instruction

        If the instruction is always executed unconditionally, or we cannot reason about the instruction,
        the value of the field is `InstructionCondition.UNDETERMINED`.

        If the instruction is executed conditionally, and we can be absolutely
        sure that it will be executed, the value of the field is `InstructionCondition.TRUE`.

        In all other cases, it is set to `InstructionCondition.FALSE`.
        """

        instruction.condition = self.condition(instruction, emu)

    # Subclasses should override
    def condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        return InstructionCondition.UNDETERMINED

    def enhance_next(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        Set the `next` and `target` field of the instruction.

        By default, it is set to the address of the next linear
        instruction.

        `next` is the address that the PC would be upon using the GDB `nexti` command,
        `target` is the jump target whether or not the jump is taken, like `stepi` and assuming the jump is taken.

        If the instruction is a non-"call" branch and either:
        - Is unconditional, or is conditional and is known to be taken, a
        - Is conditional, but is known to be taken

        And the target can be resolved, it is set to the address
        of the jump target.

        """
        next_addr: int | None = None

        # The order for the following statements in determining the next executed instruction is important
        #
        # Firstly, we check the condition field - this field is manually set by our enhancement code
        # There are cases where the Unicorn emulator is incorrect - for example, delay slots in MIPS causing jumps to not resolve correctly
        # due to the way to step using the emulator. We want our own manualy checks to override the emulator

        if instruction.condition == InstructionCondition.TRUE or instruction.is_unconditional_jump:
            # If condition is true, then this might be a conditional jump
            # There are some other instructions that run conditionally though - resolve_target returns None in those cases
            # Or, if this is a unconditional jump, we will try to resolve the next instruction run
            next_addr = self.resolve_target(instruction, emu)

        # Secondly, attempt to use emulation if we could not resolve the target above, or don't have custom condition handler for the architecture yet
        if next_addr is None and emu:
            # Use emulator to determine the next address:
            # 1. Only use it to determine non-call's (`nexti` should step over calls)
            # 2. Make sure we haven't manually set .conditional to False (which should override the emulators prediction)
            if (
                CS_GRP_CALL not in instruction.groups_set
                and instruction.condition != InstructionCondition.FALSE
            ):
                next_addr = emu.pc

        # All else fails, take the next instruction in memory
        if next_addr is None:
            next_addr = instruction.address + instruction.size

        # Determine the target of this address. This is the address that the instruction could change the program counter to.
        # allowing call instructions
        instruction.target = self.resolve_target(instruction, emu, call=True)

        instruction.next = next_addr & pwndbg.gdblib.arch.ptrmask

        if instruction.target is None:
            instruction.target = instruction.next

        if instruction.can_change_instruction_pointer:
            # Only bother doing the lookup when the target is not the next address in memory:
            instruction.target_string = MemoryColor.get_address_or_symbol(instruction.target)

        if (
            instruction.operands
            and instruction.operands[0].before_value
            and instruction.operands[0].type == CS_OP_IMM
        ):
            instruction.target_const = True

    # This is the default implementation.
    # Subclasses should override this for more accurate behavior/to catch more cases. See x86.py as example
    def resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        """
        Architecture-specific hook point for enhance_next.

        Returns the value of the instruction pointer assuming this instruction executes (and any conditional jumps are taken)

        "call" specifies if we allow this to resolve call instruction targets
        """

        if CS_GRP_CALL in instruction.groups:
            if not call:
                return None
        elif CS_GRP_JUMP not in instruction.groups:
            return None

        addr = None

        # At this point, all operands have been resolved.
        # Assume only single-operand jumps.
        if len(instruction.operands) == 1:
            op = instruction.operands[0]
            addr = self.resolve_used_value(op.before_value, instruction, op, emu)
            if addr:
                addr &= pwndbg.gdblib.arch.ptrmask
        else:
            # Some architectures have jumps with multiple operands. In this case, this default implementation
            # does a simple naive check. Iterate all operands, pick the first one resolves to a symbol or lands in executable memory
            # and use that as the target

            best_guess_addr = None

            # Reversed order, just because through observation the immediates and labels are often farther right
            for op in reversed(instruction.operands):
                resolved_addr = self.resolve_used_value(op.before_value, instruction, op, emu)
                if resolved_addr:
                    resolved_addr &= pwndbg.gdblib.arch.ptrmask
                    if op.symbol:
                        best_guess_addr = resolved_addr
                    else:
                        page = pwndbg.gdblib.vmmap.find(resolved_addr)
                        if page and page.execute:
                            best_guess_addr = resolved_addr

                if best_guess_addr is not None:
                    addr = best_guess_addr
                    instruction.target_const = op.type == CS_OP_IMM
                    break

        if addr is None:
            return None

        return int(addr)

    def dump(self, instruction: PwndbgInstruction):
        """
        Debug-only method.
        """
        return repr(instruction)

    # String functions assume the .before_value and .after_value have been set
    def immediate_string(self, instruction, operand) -> str:
        value = operand.before_value

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    # Return colorized register string
    def register_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        reg = operand.reg
        name = C.register(instruction.cs_insn.reg_name(reg).upper())

        # If using emulation and we determined the value didn't change, don't colorize
        if (
            operand.before_value is not None
            and operand.after_value is not None
            and operand.before_value == operand.after_value
        ):
            return name
        else:
            return C.register_changed(name)

    # Example: return "[_IO_2_1_stdin_+16]", where the address/symbol is colorized
    def memory_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        if operand.before_value is not None:
            return f"[{MemoryColor.get_address_or_symbol(operand.before_value)}]"
        else:
            return None


generic_assistant = DisassemblyAssistant(None)
