from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

from capstone import *  # noqa: F403
from pwnlib.constants import linux

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.remote
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.color.context as C
import pwndbg.color.memory as MemoryColor
import pwndbg.color.message as MessageColor
import pwndbg.color.syntax_highlight as H
import pwndbg.enhance
import pwndbg.lib.config
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.instruction import FORWARD_JUMP_GROUP
from pwndbg.aglib.disasm.instruction import EnhancedOperand
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

pwndbg.config.add_param(
    "emulate",
    "on",
    "unicorn emulation of code from the current PC register",
    help_docstring="""\
Emulate can be:

1. off             - no emulation is performed
2. jumps-only      - emulation is done only to resolve branch instructions
3. on              - emulation is done to resolve registers/memory values etc.

Emulation can slow down Pwndbg. Disabling it may improve performance.
Emulation requires >1GB RAM being available on the system and ability to allocate RWX memory.
""",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["on", "off", "jumps-only"],
)


# Even if this is disabled, branch instructions will still have targets printed
pwndbg.config.add_param(
    "disasm-annotations",
    True,
    "display annotations for instructions",
)

pwndbg.config.add_param(
    "emulate-annotations",
    True,
    "unicorn emulation for instruction annotations",
    help_docstring="Refers to register and memory value annotations.",
)

# If this is false, emulation is only used for the current instruction (if emulate-annotations is enabled)
pwndbg.config.add_param(
    "emulate-future-annotations",
    True,
    "unicorn emulation for future instruction's annotations",
)

# Effects future instructions, as past ones have already been cached and reflect the process state at the time
pwndbg.config.add_param("disasm-telescope-depth", 3, "depth of telescope for disasm annotations")

# In disasm view, long telescoped strings might cause lines wraps
pwndbg.config.add_param(
    "disasm-telescope-string-length",
    50,
    "the number of characters in strings to display in disasm annotations",
)

pwndbg.config.add_param(
    "disasm-inline-symbols",
    True,
    "replacing constant operands with their symbol in the disassembly",
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
# or because they change privilege levels.
# There is an additional check for CS_GRP_CALL specially in the enhancement code, which we stop at
DO_NOT_EMULATE = {
    CS_GRP_INT,
    CS_GRP_INVALID,
    CS_GRP_IRET,
    # Note that we explicitly do not include the PRIVILEGE category, since
    # we may be in kernel code, and privileged instructions are just fine
    # in that case.
    # capstone.CS_GRP_PRIVILEGE,
}


def register_assign(left: str, right: str) -> str:
    return f"{left} => {right}"


def memory_assign(left: str, right: str) -> str:
    return f"{left} <= {right}"


def memory_or_register_assign(left: str, right: str, mem_assign: bool) -> str:
    """
    Used when we don't know until runtime whether a codepath will annotate a register or memory location.
    """
    return memory_assign(left, right) if mem_assign else register_assign(left, right)


# Enhances disassembly with memory values & symbols by adding member variables to an instruction
# The only public method that should be called is "enhance"
# The enhance function is passed an instance of the Unicorn emulator
#  and will .single_step() it to determine operand values before and after executing the instruction
class DisassemblyAssistant:
    architecture: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

    def __init__(self, architecture: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> None:
        self.architecture = architecture

        self.op_handlers: Dict[
            int, Callable[[PwndbgInstruction, EnhancedOperand, Emulator], int | None]
        ] = {
            CS_OP_IMM: self._parse_immediate,  # Return immediate value
            CS_OP_REG: self._parse_register,  # Return value of register
            # Handler for memory references (as dictated by Capstone), such as first operand of "mov qword ptr [rbx + rcx*4], rax"
            CS_OP_MEM: self._parse_memory,  # Return parsed address, do not dereference
        }

        # Return a string corresponding to operand. Used to reduce code duplication while printing
        # REG type wil return register name, "RAX"
        self.op_names: Dict[int, Callable[[PwndbgInstruction, EnhancedOperand], str | None]] = {
            CS_OP_IMM: self._immediate_string,
            CS_OP_REG: self._register_string,
            CS_OP_MEM: self._memory_string,
        }

    def enhance(self, instruction: PwndbgInstruction, emu: Emulator = None) -> None:
        """
        Enhance the instruction - resolving branch targets, conditionals, and adding annotations

        This is the only public method that should be called on this object externally.
        """
        # It is assumed that the emulator's pc is at the instruction's address

        # There are 3 degrees of emulation:
        # 1. No emulation at all. In this case, the `emu` parameter should be None
        # 2. Only emulate jumps - the only interaction with the emulator in this case is stepping it and reading the PC
        # 3. Full emulation - read registers and memory from the emulator as well as determining jumps

        if DEBUG_ENHANCEMENT:
            print(
                f"Start enhancing instruction at {hex(instruction.address)} - {instruction.mnemonic} {instruction.op_str}"
            )

        # Get another reference to the emulator for the purposes of jumps
        jump_emu = emu

        if pwndbg.config.emulate != "on":
            emu = None

        # For both cases below, set emu to None so we don't use it for annotation
        if emu and not bool(pwndbg.config.emulate_annotations):
            emu = None

        # Disable emulation for future annotations based on setting
        if (
            emu
            and pwndbg.aglib.regs.pc != instruction.address
            and not bool(pwndbg.config.emulate_future_annotations)
        ):
            emu = None

        # Ensure emulator's program counter is at the correct location.
        # This occurs very rarely - observed sometimes when the remote is stalling, ctrl-c, and for some reason emulator returns PC=0.
        if emu:
            if emu.pc != instruction.address:
                if DEBUG_ENHANCEMENT:
                    print(
                        f"Program counter and emu.pc do not line up: {hex(pwndbg.aglib.regs.pc)=} {hex(emu.pc)=}"
                    )
                emu = jump_emu = None

        self._prepare(instruction, emu)

        # Don't disable emulation yet, as we can use it to read the syscall register
        self._enhance_syscall(instruction, emu)

        # Disable emulation for instructions we don't want to emulate (CALL, INT, ...)
        if emu and set(instruction.groups) & DO_NOT_EMULATE:
            emu.valid = False
            emu = jump_emu = None

            if DEBUG_ENHANCEMENT:
                print("Turned off emulation - not emulating certain type of instruction")

        # This function will .single_step the emulation
        if not self._enhance_operands(instruction, emu, jump_emu):
            if jump_emu is not None and DEBUG_ENHANCEMENT:
                print(f"Emulation failed at {instruction.address=:#x}")
            emu = None
            jump_emu = None

        if jump_emu is not None:
            # We successfully used emulation for this instruction
            instruction.emulated = True

        # Set the .condition field
        self._enhance_conditional(instruction, emu)

        # Set the .target and .next fields
        self._enhance_next(instruction, emu, jump_emu)

        if bool(pwndbg.config.disasm_annotations):
            self._set_annotation_string(instruction, emu)

        # Disable emulation after CALL instructions. We do it after enhancement, as we can use emulation
        # to determine the call's target address.
        if jump_emu and instruction.call_like:
            jump_emu.valid = False
            jump_emu = None
            emu = None

            if DEBUG_ENHANCEMENT:
                print("Turned off emulation for call")

        if DEBUG_ENHANCEMENT:
            print(self.dump(instruction))
            print("Done enhancing")

    # This is run before enhancement - often used to handle edge case behavior
    def _prepare(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        return None

    # Subclasses for specific architecture should override this
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        The goal of this function is to set the `annotation` field of the instruction,
        which is the string to be printed in a disasm view.
        """
        return None

    def _enhance_operands(
        self, instruction: PwndbgInstruction, emu: Emulator, jump_emu: Emulator
    ) -> bool:
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
        if pwndbg.config.syntax_highlight:
            instruction.asm_string = syntax_highlight(instruction.asm_string)

        # Populate the "operands" list of the instruction
        # Set before_value, symbol, and str
        for op in instruction.operands:
            # Retrieve the value, either an immediate, from a register, or from memory
            op.before_value = self.op_handlers.get(op.type, lambda *a: None)(instruction, op, emu)
            if op.before_value is not None:
                # Don't mask immediates - some computations depend on their signed values
                if op.type is not CS_OP_IMM:
                    op.before_value &= pwndbg.aglib.arch.ptrmask

                if op.before_value >= 0:
                    op.symbol = MemoryColor.attempt_colorized_symbol(op.before_value)

                op.before_value_resolved = self._resolve_used_value(
                    op.before_value, instruction, op, emu
                )

                if (
                    op.symbol
                    and op.type in (CS_OP_IMM, CS_OP_MEM)
                    and pwndbg.config.disasm_inline_symbols
                ):
                    # Make an inline replacement, so `jmp 0x400122` becomes `jmp function_name`
                    instruction.asm_string = instruction.asm_string.replace(
                        hex(op.before_value), op.symbol
                    )

        # Execute the instruction
        if jump_emu and None in jump_emu.single_step():
            # This branch is taken if stepping the emulator failed
            jump_emu = None
            emu = None

        # Set after_value after single stepping the emulator
        if emu is not None:
            # after_value
            for op in instruction.operands:
                # Retrieve the value, either an immediate, from a register, or from memory
                op.after_value = self.op_handlers.get(op.type, lambda *a: None)(
                    instruction, op, emu
                )

                op.after_value_resolved = self._resolve_used_value(
                    op.after_value, instruction, op, emu
                )

                if op.after_value is not None:
                    op.after_value &= pwndbg.aglib.arch.ptrmask

        # Set .str value of operands, after emulation has been completed
        for op in instruction.operands:
            op.str = self.op_names.get(op.type, lambda *a: None)(instruction, op)

        return jump_emu is not None

    def can_reason_about_process_state(self, instruction: PwndbgInstruction) -> bool:
        """
        Determine if the program counter of the process equals the address of the instruction being enhanced.
        If so, it means we can safely reason and read from registers and memory to enhance values that
        we can add to the annotation string. This becomes relevent when NOT emulating, and is meant to
        allow more details when the PC is at the instruction being enhanced
        """
        return instruction.address == pwndbg.aglib.regs.pc

    # Delegates to "read_register", which takes Capstone ID for register.
    def _parse_register(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        reg = operand.reg
        return self._read_register(instruction, reg, emu)

    # Determine memory address of operand (Ex: in x86, mov rax, [rip + 0xd55], would return $rip_after_instruction+0xd55)
    # Subclasses override for specific architectures
    def _parse_memory(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ) -> int | None:
        return None

    def _parse_immediate(
        self, instruction: PwndbgInstruction, operand: EnhancedOperand, emu: Emulator
    ):
        return operand.imm

    def _read_register(
        self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator
    ) -> int | None:
        """
        Read value in register. Return None if cannot reason about the value in the register.
        Different architectures use registers in different patterns, so it is best to
        override this to get to best behavior for a given architecture. See x86.py as example.

        operand_id is the ID internal to Capstone
        """
        regname: str = instruction.cs_insn.reg_name(operand_id)
        return self._read_register_name(instruction, regname, emu)

    # Read register by its name
    def _read_register_name(
        self, instruction: PwndbgInstruction, regname: str, emu: Emulator
    ) -> int | None:
        if emu:
            # Will read the value of register from the emulator
            # Be concious about calling this before/after stepping the emulator
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
                print(f"Read value from process register: {pwndbg.aglib.regs[regname]}")
            return pwndbg.aglib.regs[regname]
        else:
            return None

    # Read memory of given size, taking into account emulation and being able to reason about the memory location
    def _read_memory(
        self,
        address: int,
        size: int,
        instruction: PwndbgInstruction,
        emu: Emulator,
    ) -> int | None:
        address_list = self._telescope(address, 1, instruction, emu, read_size=size)

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
    def _resolve_used_value(
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
            self._read_memory(value, pwndbg.aglib.arch.ptrsize, instruction, emu)

        return None

    def _telescope(
        self,
        address: int,
        limit: int,
        instruction: PwndbgInstruction,
        emu: Emulator,
        read_size: int = None,
    ) -> List[int]:
        """
        Dereference an address recursively - takes into account emulation.

        It will only dereference as it is safe to do so, meaning the last value in the returned list may be a pointer

        The list that the function returns is guaranteed have len >= 1
        """

        can_read_process_state = self.can_reason_about_process_state(instruction)

        if emu:
            return emu.telescope(address, limit, read_size=read_size)
        elif can_read_process_state:
            # Can reason about memory in this case.

            if read_size is not None and read_size < pwndbg.aglib.arch.ptrsize:
                result = [address]

                size_type = pwndbg.aglib.typeinfo.get_type(read_size)
                try:
                    read_value = int(
                        pwndbg.aglib.memory.get_typed_pointer_value(size_type, address)
                    )
                    result.append(read_value)
                except pwndbg.dbg_mod.Error:
                    pass

                return result

            else:
                return pwndbg.chain.get(address, limit=limit)
        else:
            # If the target address is in a non-writeable map, we can pretty safely telescope
            # This is best-effort to give a better experience

            address_list = [address]

            for _ in range(limit):
                if address_list.count(address) >= 2:
                    break

                page = pwndbg.aglib.vmmap.find(address)
                if page and not page.write:
                    try:
                        address = int(
                            pwndbg.aglib.memory.get_typed_pointer_value(
                                pwndbg.aglib.typeinfo.ppvoid, address
                            )
                        )
                        address &= pwndbg.aglib.arch.ptrmask
                        address_list.append(address)
                    except pwndbg.dbg_mod.Error:
                        break
                else:
                    break

            return address_list

        # We cannot telescope, but we can still return the address.
        # Just without any further information
        return [address]

    # Dispatch to the appropriate format handler. Pass the list returned by `telescope()` to this function
    def _telescope_format_list(self, addresses: List[int], limit: int, emu: Emulator) -> str:
        # It is assumed proper checks have been made BEFORE calling this function so that pwndbg.chain.format
        #  will return values accurate to the program state at the time of instruction executing.

        enhance_string_len = int(pwndbg.config.disasm_telescope_string_length)

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
                enhance_string_len=enhance_string_len,
            )

    @staticmethod
    def _syscall_name(number: int, arch: str) -> str | None:
        """
        Given a syscall number and architecture, returns the name of the syscall.
        E.g. execve == 59 on x86-64
        """
        arch_module = {
            "arm": linux.arm,
            "armcm": linux.arm,
            "i386": linux.i386,
            "mips": linux.mips,
            "x86-64": linux.amd64,
            "aarch64": linux.aarch64,
            "rv32": linux.riscv64,
            "rv64": linux.riscv64,
        }.get(arch)

        if arch_module is None:
            return None

        prefix = "__NR_"

        for k, v in arch_module.__dict__.items():
            if v != number:
                continue

            if not k.startswith(prefix):
                continue

            return k[len(prefix) :].lower()

        return None

    def _enhance_syscall(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if CS_GRP_INT not in instruction.groups:
            return None

        syscall_arch, syscall_register = self._get_syscall_arch_info(instruction)

        if syscall_arch is None:
            return None

        instruction.syscall = self._read_register_name(instruction, syscall_register, emu)
        if instruction.syscall is not None:
            instruction.syscall_name = (
                DisassemblyAssistant._syscall_name(instruction.syscall, syscall_arch)
                or "<unk_%d>" % instruction.syscall
            )

    def _get_syscall_arch_info(self, instruction) -> Tuple[str, str]:
        """
        Return tuple of (name of syscall architecture, syscall register name)

        Elements of the tuple will be None to indicate it's not a syscall
        """
        if pwndbg.aglib.arch.syscall_abi is None:
            return (None, None)
        return (pwndbg.aglib.arch.name, pwndbg.aglib.arch.syscall_abi.syscall_register)

    def _enhance_conditional(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        """
        Sets the `condition` of the instruction

        If the instruction is always executed unconditionally, or we cannot reason about the instruction,
        the value of the field is `InstructionCondition.UNDETERMINED`.

        If the instruction is executed conditionally, and we can be absolutely
        sure that it will be executed, the value of the field is `InstructionCondition.TRUE`.

        In all other cases, it is set to `InstructionCondition.FALSE`.
        """

        instruction.condition = self._condition(instruction, emu)

    # Subclasses should override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        return InstructionCondition.UNDETERMINED

    def _enhance_next(
        self, instruction: PwndbgInstruction, emu: Emulator, jump_emu: Emulator
    ) -> None:
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
        # due to the way we single-step the emulator. We want our own manual checks to override the emulator

        if not instruction.call_like and (
            instruction.condition == InstructionCondition.TRUE or instruction.is_unconditional_jump
        ):
            # Don't allow call instructions - we want the actual "nexti" address
            # If condition is true, then this might be a conditional jump
            # There are some other instructions that run conditionally though - resolve_target returns None in those cases
            # Or, if this is a unconditional jump, we will try to resolve target
            next_addr = self._resolve_target(instruction, emu)

        # Secondly, attempt to use emulation if we could not resolve the target above, or don't have custom condition handler for the architecture yet
        if next_addr is None and jump_emu:
            # Use emulator to determine the next address:
            # 1. Only use it to determine non-call's (`nexti` should step over calls)
            # 2. Make sure we haven't manually set .condition to False (which should override the emulators prediction)
            if not instruction.call_like and instruction.condition != InstructionCondition.FALSE:
                next_addr = jump_emu.pc

        # Handle edge case - if the target happens to be the next address in memory and it's a jump, we need this variable
        # so the disasm output is accurate.
        if next_addr is not None and instruction.is_unconditional_jump:
            instruction.force_unconditional_jump_target = True

        # All else fails, take the next instruction in memory
        if next_addr is None:
            next_addr = instruction.address + instruction.size

        # Determine the target of this address.
        # This is the address that the instruction could potentially change the program counter to, meaning that `stepi` would go to the target
        instruction.target = self._resolve_target(instruction, emu)

        instruction.next = next_addr & pwndbg.aglib.arch.ptrmask

        if instruction.target is None:
            instruction.target = instruction.next

        if instruction.has_jump_target and instruction.target >= 0:
            # Only bother doing the symbol lookup if this is a jump
            instruction.target_string = MemoryColor.get_address_or_symbol(instruction.target)

        if (
            instruction.operands
            and instruction.operands[0].before_value
            and instruction.operands[0].type == CS_OP_IMM
        ):
            instruction.target_const = True

    # This is the default implementation.
    # Subclasses should override this for more accurate behavior/to catch more cases. See x86.py as example
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        """
        Architecture-specific hook point for _enhance_next.

        Returns the program counter target of this instruction.
        Even in the case of conditional jumps, the potential target should be resolved.
        """

        # The FORWARD_JUMP_GROUP here is very specific
        # We only want this resolver to work for instructions that Capstone
        # explicitely labels as jump instructions. If we determine that another type of instruction
        # can have a target, we resolve it manually, as this manual resolver would return improper values,
        # as it is built on the assumptions of branch instructions across many architectures.
        if not bool(instruction.groups & FORWARD_JUMP_GROUP):
            return None

        addr = None

        # At this point, all operands have been resolved.
        # Assume only single-operand jumps.
        if len(instruction.operands) == 1:
            op = instruction.operands[0]
            addr = self._resolve_used_value(op.before_value, instruction, op, emu)
            if addr:
                addr &= pwndbg.aglib.arch.ptrmask
        else:
            # Some architectures have jumps with multiple operands. In this case, this default implementation
            # does a simple naive check. Iterate all operands, pick the first one resolves to a symbol or lands in executable memory
            # and use that as the target

            # Reversed order, just because through observation the immediates and labels are often farther right
            for op in reversed(instruction.operands):
                resolved_addr = self._resolve_used_value(op.before_value, instruction, op, emu)
                if resolved_addr:
                    resolved_addr &= pwndbg.aglib.arch.ptrmask
                    if op.symbol:
                        addr = resolved_addr
                    else:
                        page = pwndbg.aglib.vmmap.find(resolved_addr)
                        # When debugging a remote QEMU target, the page permissions are not accurate.
                        # In this case, if the candidate address is mapped at all, just go with it.
                        if page and (page.execute or pwndbg.aglib.remote.is_remote()):
                            addr = resolved_addr

                if addr is not None:
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
    def _immediate_string(self, instruction, operand) -> str:
        value = operand.before_value

        if abs(value) < 0x10:
            return "%i" % value

        return "%#x" % value

    def _register_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        """
        Return colorized register string
        """
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

    def _memory_string(self, instruction: PwndbgInstruction, operand: EnhancedOperand):
        """
        Example: return "[_IO_2_1_stdin_+16]", where the address/symbol is colorized
        """
        if operand.before_value is not None:
            return f"[{MemoryColor.get_address_or_symbol(operand.before_value)}]"
        else:
            return None

    def _common_generic_register_destination(
        self, instruction: PwndbgInstruction, emu: Emulator
    ) -> None:
        """
        This function can be used to annotate instructions that have a register destination.
        In the vast majority of instructions in most architectures, the destination register is the first operand.

        Using emulation, it will determine the value placed into the register, and create an annotation string based on the result.
        """

        left = instruction.operands[0]

        # Emulating determined the value that was set in the destination register
        if left.after_value is not None:
            TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

            # Telescope the address
            telescope_addresses = self._telescope(
                left.after_value,
                TELESCOPE_DEPTH + 1,
                instruction,
                emu,
                read_size=pwndbg.aglib.arch.ptrsize,
            )

            if not telescope_addresses:
                return

            instruction.annotation = register_assign(
                left.str, self._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)
            )

    def _common_cmp_annotator_builder(
        self, flags_register_name: str, char_to_separate_operands: str = "-"
    ) -> Callable[[PwndbgInstruction, Emulator], None]:
        """
        Many architectures implement near-identical `CMP`-like instructions.

        It takes two values, either subtracts, adds, or does some bit operation
        with them to set values in the flag register.

        To reduce code duplication, subclasses can use this function to create an annotator for CMP-like instructions.
        """
        FLAG_REG_NAME_DISPLAY = flags_register_name.upper()

        def handler(instruction: PwndbgInstruction, emu: Emulator):
            # If there are just two operands, we can assume we are comparing them directly, and can display the values.
            # Some architectures have variants with more operands.
            if len(instruction.operands) == 2:
                left, right = instruction.operands

                if (l_value := left.before_value_resolved) is not None and (
                    r_value := right.before_value_resolved
                ) is not None:
                    print_left, print_right = pwndbg.enhance.format_small_int_pair(l_value, r_value)
                    # Ex: "0x7f - 0x12" or "0xdffffdea + 0x8"
                    instruction.annotation = (
                        f"{print_left} {char_to_separate_operands} {print_right}"
                    )

            # Using emulation, we can determine the resulting value put into the flag register
            if emu:
                eflags_bits = pwndbg.aglib.regs.flags[flags_register_name]
                emu_eflags = emu.read_register(flags_register_name)
                eflags_formatted = C.format_flags(emu_eflags, eflags_bits)

                display_result = register_assign(FLAG_REG_NAME_DISPLAY, eflags_formatted)

                if instruction.annotation is None:
                    # First part of this function usually sets .annotation to a string. But if the instruction
                    # has more than two operands, then we don't have a way of showing them, so this avoids the "+="" below
                    instruction.annotation = display_result
                else:
                    instruction.annotation += " " * 5 + display_result

        return handler

    def _common_load_annotator(
        self,
        instruction: PwndbgInstruction,
        emu: Emulator,
        address: int | None,
        read_size: int,
        signed: bool,
        target_size: int,
        dest_str: str,
        source_str: str,
    ) -> None:
        """
        This function annotates load instructions - moving data from memory into a register.

        These instructions read `read_size` bytes from memory into a register.

        `signed`: whether or not we are loading a signed value from memory
        `target_size`: the size of the register in bytes - relevent for sign-extension
        `dest_str`: a string representing the destination register ('rax')
        `source_str`: a string representing the source address ('[0x7fffffffe138]')
        """

        if address is None:
            return

        # There are many cases we need to consider when we are loading a value from memory
        # Were we able to reason about the memory address, and dereference it?
        # Does the resolved memory address actual point into memory?
        # If the target register size is larger than the read size, then do we need sign-extension?

        # If the address is not mapped, we segfaulted
        if not pwndbg.aglib.memory.peek(address):
            instruction.annotation = MessageColor.error(
                f"<Cannot dereference [{MemoryColor.get(address)}]>"
            )
        else:
            # In this branch, it is assumed that the address IS in a mapped page
            TELESCOPE_DEPTH = max(1, int(pwndbg.config.disasm_telescope_depth))

            telescope_addresses = self._telescope(
                address,
                TELESCOPE_DEPTH,
                instruction,
                emu,
                read_size=read_size,
            )

            if len(telescope_addresses) == 1:
                # If telescope returned only 1 address (and we already know the address is in a mapped page)
                # it means we couldn't reason about the dereferenced memory.
                # In this case, simply display the address

                # As an example, this path is taken for the following case:
                # mov rdi, qword ptr [rip + 0x17d40] where the resolved memory address is in writeable memory,
                # and we are not emulating. This means we cannot savely dereference if PC is not at the current instruction address,
                # because the the memory address could have been written to by the time the instruction executes
                telescope_print = None
            else:
                if signed and read_size != target_size and len(telescope_addresses) == 2:
                    # We sign extend the value, then convert it back to the unsigned bit representation
                    final_value = bit_math.to_signed(telescope_addresses[1], read_size * 8) & (
                        (1 << (target_size * 8)) - 1
                    )
                    # If it's a signed read that required extension, it will just be a number with no special symbol/color needed
                    telescope_print = hex(final_value)
                else:
                    # Start showing at dereferenced address, hence the [1:]
                    telescope_print = f"{self._telescope_format_list(telescope_addresses[1:], TELESCOPE_DEPTH, emu)}"

            instruction.annotation = f"{dest_str}, {source_str}"

            if telescope_print is not None:
                instruction.annotation = register_assign(instruction.annotation, telescope_print)

    def _common_store_annotator(
        self,
        instruction: PwndbgInstruction,
        emu: Emulator,
        address: int | None,
        value: int | None,
        write_size: int | None,
        address_str: str,
    ) -> None:
        """
        This function annotates store functions - moving data from a register to memory.

        The `value` is truncated to match the `write_size`, if `write_size` is not None.

        The annotation will indicate if the instruction will segfault.

        `write_size`: number of bytes of `value` that will be written
        """

        if address is None:
            return

        if not pwndbg.aglib.memory.peek(address):
            instruction.annotation = MessageColor.error(
                f"<Cannot dereference [{MemoryColor.get(address)}]>"
            )
        elif value is not None:
            # To make this annotation work with emulation disabled,
            # we telescope the value that is going to be placed in the memory operand
            TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

            if write_size is not None:
                value &= (1 << (write_size * 8)) - 1

            telescope_addresses = self._telescope(
                value,
                TELESCOPE_DEPTH,
                instruction,
                emu,
            )

            instruction.annotation = memory_assign(
                address_str, self._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)
            )

    def _common_move_annotator(self, instruction: PwndbgInstruction, emu: Emulator):
        """
        This function handles annotating `MOV` type instructions - where the value of one register is placed into another.
        """
        if len(instruction.operands) == 2:
            left, right = instruction.operands
            # If we already used emulation, use the result, otherwise take the source operand before_value
            result = left.after_value or right.before_value
            if result is not None and result >= 0:
                TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

                telescope_addresses = self._telescope(
                    result,
                    TELESCOPE_DEPTH + 1,
                    instruction,
                    emu,
                )
                if not telescope_addresses:
                    return

                instruction.annotation = register_assign(
                    left.str, self._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)
                )

    def _common_binary_op_annotator(
        self,
        instruction: PwndbgInstruction,
        emu: Emulator,
        target_operand: EnhancedOperand,
        op_one: int | None,
        op_two: int | None,
        char_to_separate_operands: str,
        memory_assignment=False,
    ) -> None:
        # Ex: "0x198723 + 0x2b8"
        math_string = None

        if op_one is not None and op_two is not None:
            print_left, print_right = pwndbg.enhance.format_small_int_pair(op_one, op_two)

            math_string = f"{print_left} {char_to_separate_operands} {print_right}"

        # Using emulation, we can determine the resulting value
        if target_operand.after_value_resolved is not None:
            instruction.annotation = memory_or_register_assign(
                target_operand.str,
                MemoryColor.get_address_and_symbol(target_operand.after_value_resolved),
                memory_assignment,
            )
            if math_string:
                instruction.annotation += f" ({math_string})"
        elif math_string:
            instruction.annotation = memory_or_register_assign(
                target_operand.str, math_string, memory_assignment
            )
