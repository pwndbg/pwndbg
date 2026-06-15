"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""

from __future__ import annotations

import collections
import re
from collections.abc import Callable
from dataclasses import dataclass

from capstone6pwndbg import *  # noqa: F403

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.disasm.aarch64
import pwndbg.aglib.disasm.arm
import pwndbg.aglib.disasm.assistant
import pwndbg.aglib.disasm.loongarch64
import pwndbg.aglib.disasm.mips
import pwndbg.aglib.disasm.ppc
import pwndbg.aglib.disasm.riscv
import pwndbg.aglib.disasm.sparc
import pwndbg.aglib.disasm.x86
import pwndbg.aglib.memory
import pwndbg.emu.emulator
import pwndbg.lib.cache
import pwndbg.lib.config
from pwndbg.aglib.disasm.assistant import DEBUG_ENHANCEMENT
from pwndbg.aglib.disasm.assistant import DisassemblyAssistant
from pwndbg.aglib.disasm.instruction import ManualPwndbgInstruction
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.disasm.instruction import PwndbgInstructionImpl
from pwndbg.aglib.disasm.instruction import SplitType
from pwndbg.color import message
from pwndbg.dbg_mod import EventType
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

CapstoneSyntax = {"intel": CS_OPT_SYNTAX_INTEL, "att": CS_OPT_SYNTAX_ATT}

CAPSTONE_SYNTAX_OPTIONS_MASK = CS_OPT_SYNTAX_INTEL | CS_OPT_SYNTAX_ATT

force_register_alias = pwndbg.config.add_param(
    "disasm-reg-alias",
    False,
    "force the disassembly to use register aliases (e.g. aarch64 x29 -> fp)",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
    help_docstring="""\
The register aliasing is done by capstone, see:
https://github.com/capstone-engine/capstone/blob/next/docs/cs_v6_release_guide.md#:~:text=None.-,Register%20alias,-Register%20alias%20

Enabling this may make disassembly slower.
""",
)

# Caching strategy:
# To ensure we don't have stale register/memory information in our cached PwndbgInstruction,
# we clear the cache whenever we DON'T do a `stepi`, `nexti`, `step`, or `next` command.
# Although `stepi` and `nexti` always go to the next machine instruction in memory, `step` and `next`
# can skip over multiple when GDB has debugging symbols and sourcecode
# In order to determine that we did a `stepi`, `nexti`, `step`, or `next`, whenever the process stops,
# we check if the current program counter is at the address of one of the instructions that we
# emulated to the last time the process stopped. This allows use to skips a handful of instruction, but still retain the cache
# Any larger changes of the program counter will cause the cache to reset.

next_addresses_cache: set[int] = set()

# The disassembly system isn't able to remember that an instruction is a delay slot instruction when it is disassembled in isolation
# from the branch is belongs to.
# This cache is used to handle this. Each address points to the branch that created the delay slot.
delay_slot_cache: collections.defaultdict[int, PwndbgInstruction | None] = collections.defaultdict(
    lambda: None
)


# Register GDB event listeners for all stop events
@pwndbg.dbg.event_handler(EventType.STOP)
def enhance_cache_listener() -> None:
    if pwndbg.aglib.regs.pc not in next_addresses_cache:
        # Clear the enhanced instruction cache to ensure we don't use stale values
        computed_instruction_cache.clear()
        instruction_sequence_linked_list_map.clear()


@pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED)
@pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED)
def clear_on_reg_mem_change() -> None:
    # We clear all the future computed instructions because when we manually change a register or memory, it's often a location
    # used by the instructions at or just after the current PC, and our previously emulated future instructions might be inaccurate
    computed_instruction_cache.pop(pwndbg.aglib.regs.pc, None)
    instruction_sequence_linked_list_map.pop(pwndbg.aglib.regs.pc, None)

    for addr in next_addresses_cache:
        computed_instruction_cache.pop(addr, None)
        instruction_sequence_linked_list_map.pop(addr, None)

    next_addresses_cache.clear()


# Dict of Address -> previous instruction sequentially in memory
# Some architectures don't have fixed-sized instructions, so this is used
# to disassemble backwards linearly in memory for those cases
linear_backward_cache: collections.defaultdict[int, int] = collections.defaultdict(lambda: None)


# In order to track the sequence of instructions at runtime, we maintain a linked list, where each
# entry points to the previous instruction that was executed.
# This is populated speculatively using emulation.
@dataclass
class InstructionSequenceNode:
    """This is used to form a linked list that tracks the order of instructions execution at runtime"""

    previous: InstructionSequenceNode | None
    instruction: PwndbgInstruction


@dataclass
class InstructionSequenceSavePointer:
    """
    This allows preserving context across calls when disassembling backwards.
    It stores the node that we just processed internally.

    This is like the saveptr parameter of strtok_r.
    """

    node: InstructionSequenceNode | None


# Map addresses to their entry in the linked list.
# While the emulation may encounter this address multiple times, this map only contains a mapping for the first
# time the instruction is executed.
instruction_sequence_linked_list_map: collections.defaultdict[
    int, InstructionSequenceNode | None
] = collections.defaultdict(lambda: None)


# In case the linked list method fails (we cannot be 100% certain of instruction order),
# it is still nice to be able to display instructions behind the instruction pointer.
# This tracks the order of instructions based on the last time we disassembled them.
# Map of address to previous address
fallback_backward_cache: collections.defaultdict[int, int | None] = collections.defaultdict(
    lambda: None
)

# This allows use to retain the annotation strings from previous instructions
computed_instruction_cache: collections.defaultdict[int, PwndbgInstruction | None] = (
    collections.defaultdict(lambda: None)
)

# Maps an address to integer 0/1, indicating the Thumb mode bit for the given address.
# Value is None if Thumb bit is irrelevent or unknown.
emulated_arm_mode_cache: collections.defaultdict[int, int | None] = collections.defaultdict(
    lambda: None
)


def get_instruction_sequence_node(
    address: int, saveptr: InstructionSequenceSavePointer
) -> InstructionSequenceNode | None:
    """Return the node of the linked list at the given address, if it exists"""
    if saveptr.node is not None:
        return saveptr.node

    if (val := instruction_sequence_linked_list_map.get(address)) is not None:
        return val

    return None


def get_previous_instruction(
    address: int, use_cache: bool, linear: bool, saveptr: InstructionSequenceSavePointer
) -> PwndbgInstruction | None:
    """
    Retrieve the instruction prior to the instruction at `address`.
    """
    if linear:
        prev_address = linear_backward_cache[address]
        result = (
            one(prev_address, from_cache=use_cache, put_backward_cache=False, linear=linear)
            if prev_address
            else None
        )
        if result is None and pwndbg.aglib.arch.constant_instruction_size:
            return one(
                address - pwndbg.aglib.arch.max_instruction_size,
                from_cache=use_cache,
                put_backward_cache=False,
                linear=linear,
            )
        return result

    sequence_node = get_instruction_sequence_node(address, saveptr)

    if sequence_node is not None:
        prev_node = sequence_node.previous
        saveptr.node = prev_node
        if prev_node is not None:
            return prev_node.instruction

    prev_address = fallback_backward_cache[address]
    return (
        one(prev_address, from_cache=use_cache, put_backward_cache=False) if prev_address else None
    )


@pwndbg.lib.cache.cache_until("objfile")
def get_disassembler(cs_info: tuple[int, int]) -> Cs:
    arch, mode = cs_info

    mode |= pwndbg.aglib.arch.get_capstone_endianness()

    cs = Cs(arch, mode)

    flavor = pwndbg.dbg.x86_disassembly_flavor()
    try:
        cs.syntax = CapstoneSyntax[flavor]
        if force_register_alias:
            cs.syntax |= CS_OPT_SYNTAX_CS_REG_ALIAS
        cs.syntax |= CS_OPT_SYNTAX_NO_ALIAS_TEXT_COMPRESSED
    except CsError:
        pass
    cs.detail = True
    return cs


def one(
    address: int | None = None,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance: bool = True,
    assistant: DisassemblyAssistant | None = None,
    from_cache: bool = False,
    put_cache: bool = False,
    put_backward_cache: bool = True,
    linear: bool = False,
) -> PwndbgInstruction | None:
    """
    Return None on failure to fetch an instruction
    """

    if address is None:
        address = pwndbg.aglib.regs.pc

    if not pwndbg.aglib.memory.peek(address):
        return None

    if from_cache:
        cached = computed_instruction_cache[address]
        if cached is not None:
            return cached

    if (
        insn := get_one_instruction(address, emu, enhance=enhance, assistant=assistant)
    ) is not None:
        if put_cache:
            computed_instruction_cache[address] = insn

        if put_backward_cache:
            linear_backward_cache[insn.address + insn.size] = insn.address

            if not linear:
                fallback_backward_cache[insn.next] = insn.address
        return insn

    return None


# Get one instruction without enhancement
def one_raw(address=None) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.aglib.regs.pc

    if not pwndbg.aglib.memory.peek(address):
        return None

    return get_one_instruction(address, enhance=False)


def get(
    address: int,
    instructions: int = 1,
    emu: pwndbg.emu.emulator.Emulator | None = None,
    enhance: bool = True,
    assistant: DisassemblyAssistant | None = None,
    padding: int = 6,
) -> list[PwndbgInstruction]:
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.aglib.memory.peek(address):
        return []

    retval: list[PwndbgInstruction] = []
    for _ in range(instructions):
        i = get_one_instruction(
            address,
            emu,
            enhance=enhance,
            assistant=assistant,
            padding=padding,
        )
        if i is None:
            break
        address = i.next
        retval.append(i)

    return retval


def get_one_instruction(
    address: int,
    emu: pwndbg.emu.emulator.Emulator | None = None,
    enhance: bool = True,
    assistant: DisassemblyAssistant | None = None,
    padding: int = 6,
) -> PwndbgInstruction | None:
    """
    If passed an emulator, this will pass it to the DisassemblyAssistant which will
    single_step the emulator to determine the operand values before and after the instruction executes.
    """
    cs_info = pwndbg.aglib.arch.get_capstone_constants(address)
    if cs_info is None:
        instr = ManualPwndbgInstruction(address, padding)
        if enhance:
            pwndbg.aglib.disasm.assistant.basic_enhance(instr)
        return instr

    md = get_disassembler(cs_info)
    data = pwndbg.aglib.memory.read(address, pwndbg.aglib.arch.max_instruction_size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        pwn_ins: PwndbgInstruction = PwndbgInstructionImpl(ins, padding)

        if enhance:
            if assistant is None:
                assistant = (
                    pwndbg.aglib.disasm.disassembly.get_disassembly_assistant_for_current_arch()
                )
            assistant.enhance(pwn_ins, emu)

        return pwn_ins

    # This is reached if disassembly fails (unknown sequence of bytes)
    return None


def can_run_first_emulate() -> bool:
    """
    Disable the emulate config variable if we don't have enough memory to use it
    See https://github.com/pwndbg/pwndbg/issues/1534
    And https://github.com/unicorn-engine/unicorn/pull/1743
    """
    global first_time_emulate
    if not first_time_emulate:
        return True
    first_time_emulate = False

    try:
        from mmap import mmap

        mm = mmap(-1, 1024 * 1024 * 1024)
        mm.close()
    except OSError:
        print(
            message.error(
                "Disabling the emulation via Unicorn Engine that is used for computing branches"
                " as there isn't enough memory (1GB) to use it (since mmap(1G, RWX) failed). See also:\n"
                "* https://github.com/pwndbg/pwndbg/issues/1534\n"
                "* https://github.com/unicorn-engine/unicorn/pull/1743\n"
                "Either free your memory or explicitly set `set emulate off` in your Pwndbg config"
            )
        )
        pwndbg.config.emulate.value = "off"
        return False

    return True


first_time_emulate = True


def no_emulate_one():
    result = near(pwndbg.aglib.regs.pc, emulate=False, show_prev_insns=False)
    if result:
        return result[0][0]
    return None


def emulate_one():
    result = near(pwndbg.aglib.regs.pc, emulate=True, show_prev_insns=False)
    if result:
        return result[0][0]
    return None


def one_with_config():
    """
    Returns a single Pwndbg Instruction at the current PC.

    Emulation determined by the `pwndbg.config.emulate` setting.
    """
    result = near(
        pwndbg.aglib.regs.pc,
        emulate=bool(pwndbg.config.emulate != "off"),
        show_prev_insns=False,
    )
    if result:
        return result[0][0]
    return None


def set_visual_split(
    set_ins: PwndbgInstruction, check_ins: PwndbgInstruction, linear: bool
) -> None:
    """
    Internal helper function to set the .split property for display purposes.

    This should only be called when the callee knows that a split should be created.

    set_ins is the instruction that we are modifying

    checks_ins is the one used to check what type of split is necessary.
    The same as set_ins unless it's a delay slot.
    """
    if not linear and (
        check_ins.next != check_ins.address + check_ins.size
        or check_ins.force_unconditional_jump_target
    ):
        set_ins.split = SplitType.BRANCH_TAKEN
    else:
        set_ins.split = SplitType.BRANCH_NOT_TAKEN


# Return (list of PwndbgInstructions, index in list where instruction.address = passed in address)
def near(
    address: int,
    forward_count: int = 1,
    backward_count: int = 0,
    total_count: int | None = None,
    end_address: int | None = None,
    emulate=False,
    show_prev_insns=True,
    use_cache=False,
    linear=False,
) -> tuple[list[PwndbgInstruction], int]:
    """
    Disassembles instructions near given `address`. Passing `emulate` makes use of
    unicorn engine to emulate instructions to predict branches that will be taken.
    `show_prev_insns` makes this show previously cached instructions

    This allows us to maintain a context of surrounding instructions while
    single-stepping instructions.

    Args:
        forward_count: number of instructions forward from this instruction
        backward_count: maximum number of previously executed instructions
        total_count:
            if set, returns a list with this many instructions in total.
            The number of backward instructions is limited by `backward_count`.
            If this is set, `forward_count` is ignored.
        end_address:
            determines the maximum address (non-inclusive) that can be disassembled.
    """

    pc = pwndbg.aglib.regs.pc

    # Some architecture aren't emulated yet
    if not pwndbg.emu or pwndbg.aglib.arch.name not in pwndbg.emu.emulator.arch_to_UC:
        emulate = False

    emu: pwndbg.emu.emulator.Emulator = None

    # Emulate if program pc is at the current instruction - can't emulate at arbitrary places, because we need current
    # processor state to instantiate the emulator.
    if address == pc and emulate and (not first_time_emulate or can_run_first_emulate()):
        try:
            emu = pwndbg.emu.emulator.Emulator()
        except pwndbg.dbg_mod.Error as e:
            match = re.search(r"Memory at address (\w+) unavailable\.", str(e))
            if match:
                return ([], -1)
            raise

    # By using the same assistant for all the instructions disassembled in this pass, we can track and share information across the instructions
    assistant = pwndbg.aglib.disasm.disassembly.get_disassembly_assistant_for_current_arch()

    # Copy register values to the enhancer for use in manual register tracking
    if assistant.supports_manual_emulation and address == pc:
        for reg in pwndbg.aglib.regs.current.common:
            if (reg_value := pwndbg.aglib.regs.read_reg(reg)) is not None:
                assistant.manual_register_values.write_register(reg, reg_value)

    # Start at the current instruction using emulation if available.
    current = one(address, emu, put_cache=True, assistant=assistant, linear=linear)

    if DEBUG_ENHANCEMENT:
        if emu and not emu.last_step_succeeded:
            print("Emulator failed at first step")

    if current is None:
        return ([], -1)

    # A linked list that contains the order of instructions that emulation
    # determines will run upon uses of the "nexti" command.
    instruction_sequence_head = instruction_sequence_linked_list_map.get(address)

    if instruction_sequence_head is None:
        instruction_sequence_head = InstructionSequenceNode(None, current)
        instruction_sequence_linked_list_map[address] = instruction_sequence_head
    else:
        # We re-disassembled the instruction and enhanced it, so save the new value
        instruction_sequence_head.instruction = current

    insns: list[PwndbgInstruction] = []

    # Get previously executed instructions from the cache.
    if DEBUG_ENHANCEMENT:
        print(f"CACHE START -------------------, {current.address}")

    if show_prev_insns:
        saveptr = InstructionSequenceSavePointer(None)

        insn = get_previous_instruction(
            current.address, use_cache=use_cache, linear=linear, saveptr=saveptr
        )
        while insn is not None and len(insns) < backward_count:
            if DEBUG_ENHANCEMENT:
                print(f"Got instruction from cache, addr={insn.address:#x}")
            if insn.jump_like and insn.split == SplitType.NO_SPLIT and not insn.causes_branch_delay:
                insn.split = SplitType.BRANCH_NOT_TAKEN
            insns.append(insn)

            insn = get_previous_instruction(
                insn.address, use_cache=use_cache, linear=linear, saveptr=saveptr
            )
        insns.reverse()

    if total_count is not None:
        target_instruction_count = total_count
    else:
        target_instruction_count = len(insns) + forward_count

    index_of_current_instruction = len(insns)
    insns.append(current)

    if DEBUG_ENHANCEMENT:
        print("END CACHE -------------------")

    # At this point, we've already added everything *BEFORE* the requested address,
    # and the instruction at 'address'.
    # Now, continue forwards.

    # A set of all the addresses after the PC that we have disassembled in this pass
    new_addresses_seen: set[int] = set()

    next_addresses_cache.clear()
    next_addresses_cache.add(current.target)

    insn = current

    last_emulated_thumb_bit_value: int | None = None

    while insn and len(insns) < target_instruction_count:
        target = insn.next if not linear else insn.address + insn.size

        if end_address is not None and target >= end_address:
            break

        # Emulation may have failed or been disabled in the last call to one()
        if emu:
            if not emu.last_step_succeeded or not emu.valid:
                emu = None
            else:
                # Upon execution the previous instruction, the Thumb mode bit may have changed.
                # This means we know whether the next instruction executed will be Thumb or not.
                # This returns None in the case the Thumb bit is not relevent.
                last_emulated_thumb_bit_value = emulated_arm_mode_cache[emu.pc()] = (
                    emu.read_thumb_bit()
                )

        if not emu and last_emulated_thumb_bit_value is not None:
            # The emulator may have been disabled, but while it was live we transitioned into Thumb mode.
            # We propagate the Thumb mode through the remaining instructions we disassemble.
            emulated_arm_mode_cache[target] = last_emulated_thumb_bit_value

        # Handle visual splits in the disasm view
        # We create splits in 3 conditions:
        # 1. We know the instruction is "jump_like" - it mutates the PC. We don't necessarily know the target, but know it can have one.
        # 2. The instruction has an explicitly resolved target which is not the next instruction in memory
        # 3. The instruction repeats (like x86 `REP`)
        split_insn = insn
        if insn.jump_like or insn.has_jump_target or insn.next == insn.address:
            # This branch handles delay slots. Delay slots have an interesting quirk in debuggers:
            # sometimes the debugger can pause in the delay slot, and sometimes the debugger will
            # automatically step over it.
            if insn.causes_branch_delay:
                # Delay slots are instructions after branches that always execute.
                # They offer a couple challenges because debuggers the Unicorn often cannot be paused in a delay slot instruction.
                # Single stepping on a branch will cause the debugger to execute the delay slot instruction and take the branch action.
                # This means the emulator's program counter will take on the value that the branch action dictates, and we would normally continue disassembling there.
                # Therefore, we must disassemble the delay slot instructions here as the normal codeflow will not reach them.

                delay_slot_address = insn.address + insn.size
                split_insn = one(delay_slot_address, None, put_cache=True, linear=linear)

                # There might not be a valid instruction at the branch delay slot
                if split_insn is None:
                    break

                insns.append(split_insn)

                ### Start manually handling caching related to delay slots
                next_addresses_cache.add(split_insn.address)

                delay_slot_cache[split_insn.address] = insn

                fallback_backward_cache[insn.next] = split_insn.address
                fallback_backward_cache[split_insn.address + split_insn.size] = split_insn.address
                fallback_backward_cache[split_insn.address] = insn.address

                instruction_sequence_head = InstructionSequenceNode(
                    instruction_sequence_head, split_insn
                )

                if delay_slot_address not in new_addresses_seen:
                    new_addresses_seen.add(delay_slot_address)
                    instruction_sequence_linked_list_map[delay_slot_address] = (
                        instruction_sequence_head
                    )
                ### Done handling caching stuff

                # Because the emulator failed, we manually set the address of the next instruction.
                # This is the address that typing "nexti" in GDB will take us to
                target = split_insn.address + split_insn.size

                if not insn.call_like and (
                    insn.is_unconditional_jump or insn.is_conditional_jump_taken
                ):
                    target = insn.target

            set_visual_split(split_insn, insn, linear)

        # Handle edge case where debugger is paused on the delay slot instruction
        # Force the disassembly flow to follow the direction of the branch
        if (cached_ins := delay_slot_cache[insn.address]) is not None:
            if not cached_ins.call_like and (
                cached_ins.is_unconditional_jump or cached_ins.is_conditional_jump_taken
            ):
                target = insn.next = cached_ins.next

            set_visual_split(insn, cached_ins, linear)

        next_addresses_cache.add(target)

        # The emulator is stepped within this call
        insn = one(target, emu, put_cache=True, assistant=assistant, linear=linear)

        if insn:
            # Add the instruction to the front of the linked list tracking the dynamic instruction sequence.
            instruction_sequence_head = InstructionSequenceNode(instruction_sequence_head, insn)

            # We want to add for the first time an instruction is encountered
            # in the current disassembly flow.
            if target not in new_addresses_seen:
                new_addresses_seen.add(target)
                instruction_sequence_linked_list_map[target] = instruction_sequence_head

            insns.append(insn)

    # Remove repeated instructions at the end of disassembly.
    # Always ensure we display the current and *next* instruction,
    # but any repeats after that are removed.
    #
    # This helps with infinite loops and RET sleds.

    while insns and len(insns) > 2 and insns[-3].address == insns[-2].address == insns[-1].address:
        del insns[-1]

    return (insns, index_of_current_instruction)


ALL_DISASSEMBLY_ASSISTANTS: dict[
    PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Callable[[], DisassemblyAssistant]
] = {
    "aarch64": lambda: pwndbg.aglib.disasm.aarch64.AArch64DisassemblyAssistant("aarch64"),
    "i8086": lambda: pwndbg.aglib.disasm.x86.X86DisassemblyAssistant("i8086"),
    "i386": lambda: pwndbg.aglib.disasm.x86.X86DisassemblyAssistant("i386"),
    "x86-64": lambda: pwndbg.aglib.disasm.x86.X86DisassemblyAssistant("x86-64"),
    "arm": lambda: pwndbg.aglib.disasm.arm.ArmDisassemblyAssistant("arm", "cpsr"),
    "armcm": lambda: pwndbg.aglib.disasm.arm.ArmDisassemblyAssistant("armcm", "xpsr"),
    "mips": lambda: pwndbg.aglib.disasm.mips.MipsDisassemblyAssistant("mips"),
    "rv32": lambda: pwndbg.aglib.disasm.riscv.RISCVDisassemblyAssistant("rv32"),
    "rv64": lambda: pwndbg.aglib.disasm.riscv.RISCVDisassemblyAssistant("rv64"),
    "loongarch64": lambda: pwndbg.aglib.disasm.loongarch64.Loong64DisassemblyAssistant(
        "loongarch64"
    ),
    "powerpc": lambda: pwndbg.aglib.disasm.ppc.PowerPCDisassemblyAssistant("powerpc"),
    "sparc": lambda: pwndbg.aglib.disasm.sparc.SparcDisassemblyAssistant("sparc"),
}


def get_disassembly_assistant_for_current_arch() -> DisassemblyAssistant:
    # If a specific subclass has not been created for the given arc, return the generic assistant
    return ALL_DISASSEMBLY_ASSISTANTS.get(
        pwndbg.aglib.arch.name, lambda: DisassemblyAssistant(None)
    )()


def arch_has_disassembly_assistant(arch: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE | None = None) -> bool:
    if arch is None:
        arch = pwndbg.aglib.arch.name

    return arch in ALL_DISASSEMBLY_ASSISTANTS
