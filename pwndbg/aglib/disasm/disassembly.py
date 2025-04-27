"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""

from __future__ import annotations

import collections
import re
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

from capstone import *  # noqa: F403

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.disasm.aarch64
import pwndbg.aglib.disasm.arm
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.disasm.loongarch64
import pwndbg.aglib.disasm.mips
import pwndbg.aglib.disasm.riscv
import pwndbg.aglib.disasm.x86
import pwndbg.aglib.memory
import pwndbg.emu.emulator
import pwndbg.lib.cache
from pwndbg.aglib.disasm.arch import DEBUG_ENHANCEMENT
from pwndbg.aglib.disasm.arch import DisassemblyAssistant
from pwndbg.aglib.disasm.instruction import ManualPwndbgInstruction
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.disasm.instruction import PwndbgInstructionImpl
from pwndbg.aglib.disasm.instruction import SplitType
from pwndbg.color import message
from pwndbg.dbg import EventType
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

CapstoneEndian = {
    "little": CS_MODE_LITTLE_ENDIAN,
    "big": CS_MODE_BIG_ENDIAN,
}

CapstoneSyntax = {"intel": CS_OPT_SYNTAX_INTEL, "att": CS_OPT_SYNTAX_ATT}


# Caching strategy:
# To ensure we don't have stale register/memory information in our cached PwndbgInstruction,
# we clear the cache whenever we DON'T do a `stepi`, `nexti`, `step`, or `next` command.
# Although `stepi` and `nexti` always go to the next machine instruction in memory, `step` and `next`
# can skip over multiple when GDB has debugging symbols and sourcecode
# In order to determine that we did a `stepi`, `nexti`, `step`, or `next`, whenever the process stops,
# we check if the current program counter is at the address of one of the instructions that we
# emulated to the last time the process stopped. This allows use to skips a handful of instruction, but still retain the cache
# Any larger changes of the program counter will cause the cache to reset.

next_addresses_cache: Set[int] = set()


# Register GDB event listeners for all stop events
@pwndbg.dbg.event_handler(EventType.STOP)
def enhance_cache_listener() -> None:
    # Clear the register value cache to ensure we get the correct program counter value
    pwndbg.aglib.regs.read_reg.cache.clear()  # type: ignore[attr-defined]

    if pwndbg.aglib.regs.pc not in next_addresses_cache:
        # Clear the enhanced instruction cache to ensure we don't use stale values
        computed_instruction_cache.clear()


@pwndbg.dbg.event_handler(EventType.MEMORY_CHANGED)
@pwndbg.dbg.event_handler(EventType.REGISTER_CHANGED)
def clear_on_reg_mem_change() -> None:
    # We clear all the future computed instructions because when we manually change a register or memory, it's often a location
    # used by the instructions at or just after the current PC, and our previously emulated future instructions might be inaccurate
    computed_instruction_cache.pop(pwndbg.aglib.regs.pc, None)

    for addr in next_addresses_cache:
        computed_instruction_cache.pop(addr, None)

    next_addresses_cache.clear()


# Dict of Address -> previous Address executed
# Used to display instructions that led to current instruction
backward_cache: DefaultDict[int, int] = collections.defaultdict(lambda: None)

# This allows use to retain the annotation strings from previous instructions
computed_instruction_cache: DefaultDict[int, PwndbgInstruction] = collections.defaultdict(
    lambda: None
)

# Maps an address to integer 0/1, indicating the Thumb mode bit for the given address.
# Value is None if Thumb bit is irrelevent or unknown.
emulated_arm_mode_cache: DefaultDict[int, int | None] = collections.defaultdict(lambda: None)


@pwndbg.lib.cache.cache_until("objfile")
def get_disassembler(address: int, cs_info: Tuple[int, int] = None):
    if cs_info is not None:
        arch, mode = cs_info
    else:
        arch, mode = pwndbg.aglib.arch.get_capstone_constants(address)

    mode |= CapstoneEndian[pwndbg.aglib.arch.endian]

    cs = Cs(arch, mode)

    flavor = pwndbg.dbg.x86_disassembly_flavor()
    try:
        cs.syntax = CapstoneSyntax[flavor]
    except CsError:
        pass
    cs.detail = True
    return cs


def get_one_instruction(
    address,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance=True,
    from_cache=False,
    put_cache=False,
    assistant: DisassemblyAssistant = None,
) -> PwndbgInstruction:
    """
    If passed an emulator, this will pass it to the DisassemblyAssistant which will
    single_step the emulator to determine the operand values before and after the instruction executes.
    """
    if from_cache:
        cached = computed_instruction_cache[address]
        if cached is not None:
            return cached

    cs_info = pwndbg.aglib.arch.get_capstone_constants(address)
    if cs_info is None:
        return ManualPwndbgInstruction(address)

    md = get_disassembler(address, cs_info)
    data = pwndbg.aglib.memory.read(address, pwndbg.aglib.arch.max_instruction_size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        pwn_ins: PwndbgInstruction = PwndbgInstructionImpl(ins)

        if enhance:
            if assistant is None:
                assistant = (
                    pwndbg.aglib.disasm.disassembly.get_disassembly_assistant_for_current_arch()
                )
            assistant.enhance(pwn_ins, emu)

        if put_cache:
            computed_instruction_cache[address] = pwn_ins

        return pwn_ins

    # Make linter happy. This shouldn't occur as md.disasm would crash first.
    return None


# Return None on failure to fetch an instruction
def one(
    address=None,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance=True,
    from_cache=False,
    put_cache=False,
    put_backward_cache=True,
    assistant: DisassemblyAssistant = None,
) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.aglib.regs.pc

    if not pwndbg.aglib.memory.peek(address):
        return None

    # A for loop in case this returns an empty list
    for insn in get(
        address,
        1,
        emu,
        enhance=enhance,
        from_cache=from_cache,
        put_cache=put_cache,
        assistant=assistant,
    ):
        if put_backward_cache:
            backward_cache[insn.next] = insn.address
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
    address,
    instructions=1,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance=True,
    from_cache=False,
    put_cache=False,
    assistant: DisassemblyAssistant = None,
) -> List[PwndbgInstruction]:
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.aglib.memory.peek(address):
        return []

    retval: List[PwndbgInstruction] = []
    for _ in range(instructions):
        i = get_one_instruction(
            address,
            emu,
            enhance=enhance,
            from_cache=from_cache,
            put_cache=put_cache,
            assistant=assistant,
        )
        if i is None:
            break
        address = i.next
        retval.append(i)

    return retval


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
        emulate=bool(not pwndbg.config.emulate == "off"),
        show_prev_insns=False,
    )
    if result:
        return result[0][0]
    return None


# Return (list of PwndbgInstructions, index in list where instruction.address = passed in address)
def near(
    address, instructions=1, emulate=False, show_prev_insns=True, use_cache=False, linear=False
) -> Tuple[List[PwndbgInstruction], int]:
    """
    Disasms instructions near given `address`. Passing `emulate` makes use of
    unicorn engine to emulate instructions to predict branches that will be taken.
    `show_prev_insns` makes this show previously cached instructions
    (this is mostly used by context's disasm display, so user see what was previously)
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
            else:
                raise

    # By using the same assistant for all the instructions disassembled in this pass, we can track and share information across the instructions
    assistant = pwndbg.aglib.disasm.disassembly.get_disassembly_assistant_for_current_arch()

    # Start at the current instruction using emulation if available.
    current = one(address, emu, put_cache=True, assistant=assistant)

    if DEBUG_ENHANCEMENT:
        if emu and not emu.last_step_succeeded:
            print("Emulator failed at first step")

    if current is None:
        return ([], -1)

    insns: List[PwndbgInstruction] = []

    # Get previously executed instructions from the cache.
    if DEBUG_ENHANCEMENT:
        print(f"CACHE START -------------------, {current.address}")

    if show_prev_insns:
        cached = backward_cache[current.address]
        insn = one(cached, from_cache=use_cache, put_backward_cache=False) if cached else None
        while insn is not None and len(insns) < instructions:
            if DEBUG_ENHANCEMENT:
                print(f"Got instruction from cache, addr={cached:#x}")
            if insn.jump_like and insn.split == SplitType.NO_SPLIT and not insn.causes_branch_delay:
                insn.split = SplitType.BRANCH_NOT_TAKEN
            insns.append(insn)
            cached = backward_cache[insn.address]
            insn = one(cached, from_cache=use_cache, put_backward_cache=False) if cached else None
        insns.reverse()

    index_of_current_instruction = len(insns)

    insns.append(current)

    if DEBUG_ENHANCEMENT:
        print("END CACHE -------------------")

    # At this point, we've already added everything *BEFORE* the requested address,
    # and the instruction at 'address'.
    # Now, continue forwards.

    next_addresses_cache.clear()
    next_addresses_cache.add(current.target)

    insn = current
    total_instructions = 1 + (2 * instructions)

    last_emulated_thumb_bit_value: int | None = None

    while insn and len(insns) < total_instructions:
        target = insn.next if not linear else insn.address + insn.size

        # Emulation may have failed or been disabled in the last call to one()
        if emu:
            if not emu.last_step_succeeded or not emu.valid:
                emu = None
            else:
                # Upon execution the previous instruction, the Thumb mode bit may have changed.
                # This means we know whether the next instruction executed will be Thumb or not.
                # This returns None in the case the Thumb bit is not relevent.
                last_emulated_thumb_bit_value = emulated_arm_mode_cache[emu.pc] = (
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
        if insn.jump_like or insn.has_jump_target or insn.next == insn.address:
            split_insn = insn

            # If this instruction has a delay slot, disassemble the delay slot instruction
            # And append it to the list
            if insn.causes_branch_delay:
                # Delay slots are instructions after branches that always execute.
                # Unicorn cannot be paused in a delay slot instruction.
                # Single stepping on a branch will cause Unicorn to execute the delay slot instruction and take the branch action.
                # This means the emulator's program counter will take on the value that the branch action dictates, and we would normally continue disassembling there.
                # We disassemble the delay slot instructions here as the normal codeflow will not reach them.

                split_insn = one(insn.address + insn.size, None, put_cache=True)

                # There might not be a valid instruction at the branch delay slot
                if split_insn is None:
                    break

                insns.append(split_insn)

                # Manually make the backtracing cache correct
                backward_cache[insn.next] = split_insn.address
                backward_cache[split_insn.address + split_insn.size] = split_insn.address
                backward_cache[split_insn.address] = insn.address

                # Because the emulator failed, we manually set the address of the next instruction.
                # This is the address that typing "nexti" in GDB will take us to
                target = split_insn.address + split_insn.size

                if not insn.call_like and (
                    insn.is_unconditional_jump or insn.is_conditional_jump_taken
                ):
                    target = insn.target

            if not linear and (
                insn.next != insn.address + insn.size or insn.force_unconditional_jump_target
            ):
                split_insn.split = SplitType.BRANCH_TAKEN
            else:
                split_insn.split = SplitType.BRANCH_NOT_TAKEN

        # Address to disassemble & emulate
        next_addresses_cache.add(target)

        # The emulator is stepped within this call
        insn = one(target, emu, put_cache=True, assistant=assistant)

        if insn:
            insns.append(insn)

    # Remove repeated instructions at the end of disassembly.
    # Always ensure we display the current and *next* instruction,
    # but any repeats after that are removed.
    #
    # This helps with infinite loops and RET sleds.

    while insns and len(insns) > 2 and insns[-3].address == insns[-2].address == insns[-1].address:
        del insns[-1]

    return (insns, index_of_current_instruction)


ALL_DISASSEMBLY_ASSISTANTS: Dict[
    PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Callable[[], DisassemblyAssistant]
] = {
    "aarch64": lambda: pwndbg.aglib.disasm.aarch64.AArch64DisassemblyAssistant("aarch64"),
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
