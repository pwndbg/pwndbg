"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""

from __future__ import annotations

import collections
import re
import typing
from dataclasses import dataclass
from typing import Any
from typing import DefaultDict
from typing import List
from typing import Union

import capstone
import gdb
from capstone import *  # noqa: F403

import pwndbg.disasm.arch
import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.ida
import pwndbg.lib.cache
from pwndbg.color import message
from pwndbg.disasm.arch import DEBUG_ENHANCEMENT
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.disasm.instruction import make_simple_instruction

try:
    import pwndbg.emu.emulator
except Exception:
    pwndbg.emu = None

CapstoneArch = {
    "arm": CS_ARCH_ARM,
    "armcm": CS_ARCH_ARM,
    "aarch64": CS_ARCH_ARM64,
    "i386": CS_ARCH_X86,
    "i8086": CS_ARCH_X86,
    "x86-64": CS_ARCH_X86,
    "powerpc": CS_ARCH_PPC,
    "mips": CS_ARCH_MIPS,
    "sparc": CS_ARCH_SPARC,
    "rv32": CS_ARCH_RISCV,
    "rv64": CS_ARCH_RISCV,
}

CapstoneEndian = {
    "little": CS_MODE_LITTLE_ENDIAN,
    "big": CS_MODE_BIG_ENDIAN,
}

CapstoneMode = {4: CS_MODE_32, 8: CS_MODE_64}

CapstoneSyntax = {"intel": CS_OPT_SYNTAX_INTEL, "att": CS_OPT_SYNTAX_ATT}

# For variable-instruction-width architectures
# (x86 and amd64), we keep a cache of instruction
# sizes, and where the end of the instruction falls.
#
# This allows us to consistently disassemble backward.
VariableInstructionSizeMax = {
    "i386": 16,
    "x86-64": 16,
    "i8086": 16,
    "mips": 8,
    "rv32": 22,
    "rv64": 22,
}


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

# Register GDB event listeners for all stop events
@pwndbg.gdblib.events.stop
def enhance_cache_listener() -> None:
    # Clear the register value cache to ensure we get the correct program counter value
    pwndbg.gdblib.regs.__getattr__.cache.clear()

    if(pwndbg.gdblib.regs.pc not in next_addresses_cache):
        # Clear the enhanced instruction cache to ensure we don't use stale values
        computed_instruction_cache.clear()

@pwndbg.gdblib.events.mem_changed
@pwndbg.gdblib.events.reg_changed
def clear_on_reg_mem_change() -> None:
    
    # We clear all the future computed instructions because when we manually change a register or memory, it's often a location
    # used by the instructions at or just after the current PC, and our previously emulated future instructions might be inaccurate
    for addr in next_addresses_cache:
        computed_instruction_cache.pop(addr, None)

    next_addresses_cache.clear()


# Dict of Address -> previous Address executed
# This allows use to display the instructions that led to the current instruction
backward_cache: DefaultDict[int, int] = collections.defaultdict(lambda: None)

# This allows use to retain the annotation strings from previous instructions
computed_instruction_cache: DefaultDict[int, PwndbgInstruction] = collections.defaultdict(
    lambda: None
)


@pwndbg.lib.cache.cache_until("objfile")
def get_disassembler_cached(arch, ptrsize: int, endian, extra=None):
    arch = CapstoneArch[arch]

    if extra is None:
        mode = CapstoneMode[ptrsize]
    else:
        mode = extra

    mode |= CapstoneEndian[endian]

    try:
        flavor = gdb.execute("show disassembly-flavor", to_string=True).lower().split('"')[1]
    except gdb.error as e:
        if str(e).find("disassembly-flavor") > -1:
            flavor = "intel"
        else:
            raise

    cs = Cs(arch, mode)
    try:
        cs.syntax = CapstoneSyntax[flavor]
    except CsError:
        pass
    cs.detail = True
    return cs


def get_disassembler(pc):
    if pwndbg.gdblib.arch.current == "armcm":
        # novermin
        extra = (
            (CS_MODE_MCLASS | CS_MODE_THUMB)
            if (pwndbg.gdblib.regs.xpsr & (1 << 24))
            else CS_MODE_MCLASS
        )

    elif pwndbg.gdblib.arch.current in ("arm", "aarch64"):
        extra = CS_MODE_THUMB if (pwndbg.gdblib.regs.cpsr & (1 << 5)) else CS_MODE_ARM

    elif pwndbg.gdblib.arch.current == "sparc":
        if "v9" in gdb.newest_frame().architecture().name():
            extra = CS_MODE_V9
        else:
            # The ptrsize base modes cause capstone.CsError: Invalid mode (CS_ERR_MODE)
            extra = 0

    elif pwndbg.gdblib.arch.current == "i8086":
        extra = CS_MODE_16

    elif (
        pwndbg.gdblib.arch.current == "mips"
        and "isa32r6" in gdb.newest_frame().architecture().name()
    ):
        extra = CS_MODE_MIPS32R6

    elif pwndbg.gdblib.arch.current == "rv32":
        extra = CS_MODE_RISCV32 | CS_MODE_RISCVC  # novermin
    elif pwndbg.gdblib.arch.current == "rv64":
        extra = CS_MODE_RISCV64 | CS_MODE_RISCVC  # novermin

    else:
        extra = None

    return get_disassembler_cached(
        pwndbg.gdblib.arch.current, pwndbg.gdblib.arch.ptrsize, pwndbg.gdblib.arch.endian, extra
    )


# TODO: FIX THIS
# @pwndbg.lib.cache.cache_until("cont")
# If passed an emulator, this will pass it to the DisassemblyAssistant
# which will single_step the emulator to determine the operand values before and after the instruction executes
def get_one_instruction(
    address,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance=True,
    from_cache=False,
    put_cache=False,
) -> PwndbgInstruction:
    if from_cache:
        cached = computed_instruction_cache[address]
        if cached is not None:
            return cached

    if pwndbg.gdblib.arch.current not in CapstoneArch:
        return make_simple_instruction(address)

    md = get_disassembler(address)
    size = VariableInstructionSizeMax.get(pwndbg.gdblib.arch.current, 4)
    data = pwndbg.gdblib.memory.read(address, size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        pwn_ins = PwndbgInstruction(ins)

        if enhance:
            pwndbg.disasm.arch.DisassemblyAssistant.enhance(pwn_ins, emu)

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
) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.gdblib.regs.pc

    if not pwndbg.gdblib.memory.peek(address):
        return None

    # A for loop in case this returns an empty list
    for insn in get(address, 1, emu, enhance=enhance, from_cache=from_cache, put_cache=put_cache):
        backward_cache[insn.next] = insn.address
        return insn

    return None


# Get one instruction without enhancement
def one_raw(address=None) -> PwndbgInstruction | None:
    if address is None:
        address = pwndbg.gdblib.regs.pc

    if not pwndbg.gdblib.memory.peek(address):
        return None

    return get_one_instruction(address, enhance=False)


def get(
    address,
    instructions=1,
    emu: pwndbg.emu.emulator.Emulator = None,
    enhance=True,
    from_cache=False,
    put_cache=False,
) -> list[PwndbgInstruction]:
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.gdblib.memory.peek(address):
        return []

    retval: list[PwndbgInstruction] = []
    for _ in range(instructions):
        i = get_one_instruction(
            address, emu, enhance=enhance, from_cache=from_cache, put_cache=put_cache
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
        from mmap import mmap, MAP_ANON, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE  # isort:skip

        mm = mmap(  # novm
            -1, 1024 * 1024 * 1024, MAP_PRIVATE | MAP_ANON, PROT_WRITE | PROT_READ | PROT_EXEC
        )
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
        gdb.execute("set emulate off", to_string=True)
        return False

    return True


first_time_emulate = True


# Return (list of PwndbgInstructions, index in list where instruction.address = passed in address)
def near(
    address, instructions=1, emulate=False, show_prev_insns=True, use_cache=False
) -> tuple[list[PwndbgInstruction], int]:
    """
    Disasms instructions near given `address`. Passing `emulate` makes use of
    unicorn engine to emulate instructions to predict branches that will be taken.
    `show_prev_insns` makes this show previously cached instructions
    (this is mostly used by context's disasm display, so user see what was previously)
    """

    pc = pwndbg.gdblib.regs.pc

    # Some architecture aren't emulated yet
    if not pwndbg.emu or pwndbg.gdblib.arch.current not in pwndbg.emu.emulator.arch_to_UC:
        emulate = False

    emu: pwndbg.emu.emulator.Emulator = None

    # Emulate if program pc is at the current instruction - can't emulate at arbitrary places, because we need current
    # processor state to instantiate the emulator.
    if address == pc and emulate and (not first_time_emulate or can_run_first_emulate()):
        try:
            emu = pwndbg.emu.emulator.Emulator()
        except gdb.error as e:
            message = str(e)
            match = re.search(r"Memory at address (\w+) unavailable\.", message)
            if match:
                return ([], -1)
            else:
                raise

    # Start at the current instruction using emulating if available.
    current = one(address, emu, put_cache=True)

    if DEBUG_ENHANCEMENT:
        if emu and not emu.last_step_succeeded:
            print("Emulator failed at first step")

    if current is None:
        return ([], -1)
    


    insns: list[PwndbgInstruction] = []

    # Get previously executed instructions from the cache.
    if DEBUG_ENHANCEMENT:
        print(f"CACHE START -------------------, {current.address}")

    if show_prev_insns:
        cached = backward_cache[current.address]
        insn = one(cached, from_cache=use_cache) if cached else None
        while insn is not None and len(insns) < instructions:
            if DEBUG_ENHANCEMENT:
                print(f"Got instruction from cache, addr={cached:#x}")
            insns.append(insn)
            cached = backward_cache[insn.address]
            insn = one(cached, from_cache=use_cache) if cached else None
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

    while insn and len(insns) < total_instructions:
        # Emulation may have failed or been disabled in the last call to one()
        if emu:
            if not emu.last_step_succeeded or not emu.valid:
                emu = None

        # Address to disassemble & emulate
        target = insn.next
        next_addresses_cache.add(target)

        # The emulator is stepped within this call
        insn = one(target, emu, put_cache=True)

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
