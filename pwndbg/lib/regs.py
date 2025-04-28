"""
Reading register value from the inferior, and provides a
standardized interface to registers like "sp" and "pc".
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict
from typing import Iterator
from typing import List
from typing import OrderedDict
from typing import Set
from typing import Tuple
from typing import Union

import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE

BitFlags = OrderedDict[str, Union[int, Tuple[int, int]]]


@dataclass
class UnicornRegisterWrite:
    """
    Represent a register to write to the Unicorn emulator.
    """

    name: str
    force_write: bool


@dataclass
class Reg:
    name: str
    size: int | None = None
    """Register width in bytes. None if the register size is arch.ptrsize"""
    offset: int = 0
    """Relevant for subregisters - the offset of this register in the main register"""
    zero_extend_writes: bool = False
    """Upon writing a value to this subregister, are the higher bits of the full register zeroed out?"""
    subregisters: tuple[Reg, ...] = ()


class RegisterSet:
    #: Program counter register
    pc: str

    #: Stack pointer register
    stack: str

    #: Frame pointer register
    frame: str | None = None

    #: Return address register
    retaddr: Tuple[str, ...]

    #: Flags register (eflags, cpsr)
    flags: Dict[str, BitFlags]

    #: List of native-size general-purpose registers
    gpr: Tuple[str, ...]

    #: List of miscellaneous, valid registers
    misc: Tuple[str, ...]

    #: Register-based arguments for most common ABI
    args: Tuple[str, ...]

    #: Return value register
    retval: str | None

    #: Common registers which should be displayed in the register context
    common: List[str] = []

    #: All valid registers
    all: Set[str]

    #: Reg objects containing information on each register
    reg_definitions: Dict[str, Reg]

    #: Map of register name to the full register it resides in. Example mapping: "eax" -> Reg("rax")
    full_register_lookup: Dict[str, Reg]

    def __init__(
        self,
        pc: Reg = Reg("pc"),
        stack: Reg = Reg("sp"),
        frame: Reg | None = None,
        retaddr: Tuple[Reg, ...] = (),
        flags: Dict[str, BitFlags] = {},
        extra_flags: Dict[str, BitFlags] = {},
        gpr: Tuple[Reg, ...] = (),
        misc: Tuple[str, ...] = (),
        args: Tuple[str, ...] = (),
        retval: str | None = None,
    ) -> None:
        self.pc = pc.name
        self.stack = stack.name
        self.frame = frame.name if frame else None
        self.retaddr = tuple(x.name for x in retaddr)
        self.flags = flags
        self.extra_flags = extra_flags
        self.gpr = tuple(x.name for x in gpr)
        self.misc = misc
        self.args = args
        self.retval = retval

        all_subregisters: List[str] = []

        self.reg_definitions = {}
        self.full_register_lookup = {}
        for reg in itertools.chain(gpr, (stack, frame, pc), retaddr):
            if reg:
                self.reg_definitions[reg.name] = reg
                self.full_register_lookup[reg.name] = reg
                for subregister in reg.subregisters:
                    self.reg_definitions[subregister.name] = subregister
                    self.full_register_lookup[subregister.name] = reg
                    all_subregisters.append(subregister.name)

        # In 'common', we don't want to lose the ordering of:
        self.common = []
        for regname in itertools.chain(
            self.gpr, (self.frame, self.stack, self.pc), tuple(self.flags)
        ):
            if regname and regname not in self.common:
                self.common.append(regname)

        # The specific order of this list is very important:
        # Due to the behavior of Arm in the Unicorn engine,
        # we must write the flags register after PC, and the stack pointer after the flags register.
        # Otherwise, the values will be clobbered
        # https://github.com/pwndbg/pwndbg/pull/2337
        self.emulated_regs_order: List[UnicornRegisterWrite] = []

        for regname in itertools.chain(
            (self.pc,),
            tuple(self.flags),
            (self.stack, self.frame),
            self.retaddr,
            self.misc,
            self.gpr,
        ):
            if regname and regname not in self.emulated_regs_order:
                emu_reg = UnicornRegisterWrite(regname, True if regname in flags else False)
                self.emulated_regs_order.append(emu_reg)

        self.all = (
            set(self.misc)
            | set(self.flags)
            | set(self.extra_flags)
            | set(self.retaddr)
            | set(self.common)
            | set(all_subregisters)
        )
        self.all -= {None}
        self.all |= {"pc", "sp"}

    def __contains__(self, reg: str) -> bool:
        return reg in self.all

    def __iter__(self) -> Iterator[str]:
        yield from self.all


class PsuedoEmulatedRegisterFile:
    """
    This class represents a set of registers that can be written, read, and invalidated.

    The aim is to allow some manual dynamic/static analysis without the need for a full emulator.

    The implementation can handle the behavior of architectures with partial registers,
    such as x86 (Ex: rax has "eax", "ax", "ah", and "al" as subregisters) or AArch64 (Ex: X0 contains W0).
    Most of the complexity of the bitshifts and masks arise from the necessity to handle these cases.
    """

    masks: defaultdict[str, int]
    """
    Map of register name to bitmask indicating what bits of the register we know the value of.

    Example:
    {
        "rax": 0xFFFF
    }
    This indicates that in the RAX register, we only know the bottom 16 bits. This likely resulted from writing the "ax" register.
    Any attempt to read any other bits returns None. In this case, we can read from "ax", "ah", and "al", but not "eax" or "rax".
    """

    values: defaultdict[str, int]
    """
    Map of register to the value we know it to have.
    """

    register_set: RegisterSet
    ptrsize: int

    def __init__(self, register_set: RegisterSet, ptrsize: int):
        self.register_set = register_set
        self.ptrsize = ptrsize

        self.masks = defaultdict(int)
        self.values = defaultdict(int)

    def write_register(
        self, reg: str, value: int, source_width: int | None = None, sign_extend: bool = False
    ) -> None:
        """
        source_width is the byte width of the value's source.
        It should be specified when the source has a width shorter than the destination register.

        Examples:
            movsbl EAX, AL      // sign extend 1 byte register to 4 byte register
            movzbl EAX, AL      // zero extend

            Source width would be 1, and in the first case sign_extend should be set to True.
            If sign_extend is False, we zero extend.
        """
        # Definition of the register we are writing
        write_reg_def = self.register_set.reg_definitions.get(reg)
        if write_reg_def is None:
            return None

        register_bit_offset = write_reg_def.offset * 8
        written_register_size = (
            write_reg_def.size if write_reg_def.size is not None else self.ptrsize
        )
        written_register_mask = (1 << (written_register_size * 8)) - 1

        # Definition of the "full" register that the written register resides in. Might be itself.
        full_reg_def = self.register_set.full_register_lookup[reg]

        # Handle zero / sign-extension
        if source_width is not None:
            # Ensure that if value is negative, it is converted to it's unsigned representation
            value &= (1 << (source_width * 8)) - 1

            # Sign-extend the value to the write_size
            if sign_extend:
                value = bit_math.to_signed(value, source_width * 8) & written_register_mask

        # Bitmask of the register positioned in the full register. Ex: ah register is bits [15-8] in RAX.
        value_mask = written_register_mask << register_bit_offset

        # The bits we will place into the register
        written_bits = (value << register_bit_offset) & value_mask

        if write_reg_def.zero_extend_writes:
            full_reg_size = full_reg_def.size if full_reg_def.size is not None else self.ptrsize
            full_reg_mask = (1 << (full_reg_size * 8)) - 1
            # Bitmask indicating the bits that this write is setting.
            overriden_bits_mask = full_reg_mask
        else:
            overriden_bits_mask = value_mask

        # Clear bits of current value where new value is being written.
        value_masked_for_placement = self.values[full_reg_def.name] & ~overriden_bits_mask

        self.masks[full_reg_def.name] = overriden_bits_mask | self.masks[full_reg_def.name]
        self.values[full_reg_def.name] = written_bits | value_masked_for_placement

    def read_register(self, reg: str) -> int | None:
        # Definition of the register we are reading
        write_reg_def = self.register_set.reg_definitions.get(reg)
        if write_reg_def is None:
            return None

        register_bit_offset = write_reg_def.offset * 8
        written_register_size = (
            write_reg_def.size if write_reg_def.size is not None else self.ptrsize
        )
        written_register_mask = (1 << (written_register_size * 8)) - 1

        # Definition of the "full" register that the read register resides in. Might be itself.
        full_reg_def = self.register_set.full_register_lookup[reg]

        mask = self.masks[full_reg_def.name]
        if mask == 0:
            return None

        read_mask = written_register_mask << register_bit_offset

        if mask & read_mask != read_mask:
            # Not all of the bits that we are attempting to read are readable.
            return None

        return (self.values[full_reg_def.name] & read_mask) >> register_bit_offset

    def invalidate_all_registers(self) -> None:
        self.masks.clear()

    def invalidate_register(self, reg: str) -> None:
        """
        Invalidate the bits that a write to this register would override.

        This can be used when we statically detect that a register is written, but
        we don't know the concrete value that is written so we have to invalidate any current
        knowledge of the register's bits.
        """
        # Definition of the register we are invalidating
        written_reg_def = self.register_set.reg_definitions.get(reg)
        if written_reg_def is None:
            return None

        register_bit_offset = written_reg_def.offset * 8
        written_register_size = (
            written_reg_def.size if written_reg_def.size is not None else self.ptrsize
        )
        written_register_mask = (1 << (written_register_size * 8)) - 1

        # Definition of the "full" register that the written register resides in. Might be itself.
        full_reg_def = self.register_set.full_register_lookup[reg]

        value_mask = written_register_mask << register_bit_offset

        if written_reg_def.zero_extend_writes:
            full_reg_size = full_reg_def.size if full_reg_def.size is not None else self.ptrsize
            full_reg_mask = (1 << (full_reg_size * 8)) - 1
            new_mask = full_reg_mask
        else:
            new_mask = value_mask

        self.masks[full_reg_def.name] = ~new_mask & self.masks[full_reg_def.name]

    def __repr__(self):
        return str(
            {
                "masks": {x: hex(y) for x, y in self.masks.items()},
                "values": {x: hex(y) for x, y in self.values.items()},
            }
        )


arm_cpsr_flags = BitFlags(
    [
        ("N", 31),
        ("Z", 30),
        ("C", 29),
        ("V", 28),
        ("Q", 27),
        ("J", 24),
        ("T", 5),
        ("E", 9),
        ("A", 8),
        ("I", 7),
        ("F", 6),
    ]
)
arm_xpsr_flags = BitFlags([("N", 31), ("Z", 30), ("C", 29), ("V", 28), ("Q", 27), ("T", 24)])

aarch64_cpsr_flags = BitFlags(
    [
        ("N", 31),
        ("Z", 30),
        ("C", 29),
        ("V", 28),
        ("Q", 27),
        ("PAN", 22),
        ("IL", 20),
        ("D", 9),
        ("A", 8),
        ("I", 7),
        ("F", 6),
        ("EL", (2, 2)),
        ("SP", 0),
    ]
)

aarch64_sctlr_flags = BitFlags(
    [
        ("TIDCP", 63),
        ("SPINTMASK", 62),
        ("NMI", 61),
        ("EPAN", 57),
        ("ATA0", 43),
        ("ATA0", 42),
        ("TCF", (40, 2)),
        ("TCF0", (38, 2)),
        ("ITFSB", 37),
        ("BT1", 36),
        ("BT0", 35),
        ("EnIA", 31),
        ("EnIB", 30),
        ("EnDA", 27),
        ("UCI", 26),
        ("EE", 25),
        ("E0E", 24),
        ("SPAN", 23),
        ("TSCXT", 20),
        ("WXN", 19),
        ("nTWE", 18),
        ("nTWI", 16),
        ("UCT", 15),
        ("DZE", 14),
        ("EnDB", 13),
        ("I", 12),
        ("UMA", 9),
        ("SED", 8),
        ("ITD", 7),
        ("nAA", 6),
        ("CP15BEN", 5),
        ("SA0", 4),
        ("SA", 3),
        ("C", 2),
        ("A", 1),
        ("M", 0),
    ]
)

aarch64_scr_flags = BitFlags(
    [
        ("HCE", 8),
        ("SMD", 7),
        ("EA", 3),
        ("FIQ", 2),
        ("IRQ", 1),
        ("NS", 0),
    ]
)

arm = RegisterSet(
    retaddr=(Reg("lr", 4),),
    flags={"cpsr": arm_cpsr_flags},
    gpr=(
        Reg("r0", 4),
        Reg("r1", 4),
        Reg("r2", 4),
        Reg("r3", 4),
        Reg("r4", 4),
        Reg("r5", 4),
        Reg("r6", 4),
        Reg("r7", 4),
        Reg("r8", 4),
        Reg("r9", 4),
        Reg("r10", 4),
        Reg("r11", 4),
        Reg("r12", 4),
    ),
    args=("r0", "r1", "r2", "r3"),
    retval="r0",
)

# ARM Cortex-M
armcm = RegisterSet(
    retaddr=(Reg("lr", 4),),
    flags={"xpsr": arm_xpsr_flags},
    gpr=(
        Reg("r0", 4),
        Reg("r1", 4),
        Reg("r2", 4),
        Reg("r3", 4),
        Reg("r4", 4),
        Reg("r5", 4),
        Reg("r6", 4),
        Reg("r7", 4),
        Reg("r8", 4),
        Reg("r9", 4),
        Reg("r10", 4),
        Reg("r11", 4),
        Reg("r12", 4),
    ),
    args=("r0", "r1", "r2", "r3"),
    retval="r0",
)

# AArch64 has a PSTATE register, but GDB represents it as the CPSR register
aarch64 = RegisterSet(
    retaddr=(Reg("lr", 8),),
    flags={"cpsr": aarch64_cpsr_flags},
    extra_flags={
        "scr_el3": aarch64_scr_flags,
        "sctlr": aarch64_sctlr_flags,
        "sctlr_el2": aarch64_sctlr_flags,
        "sctlr_el3": aarch64_sctlr_flags,
        "spsr_el1": aarch64_cpsr_flags,
        "spsr_el2": aarch64_cpsr_flags,
        "spsr_el3": aarch64_cpsr_flags,
    },
    # X29 is the frame pointer register (FP) but setting it
    # as frame here messes up the register order to the point
    # it's confusing. Think about improving this if frame
    # pointer semantics are required for other functionalities.
    # frame   = 'x29',
    gpr=(
        Reg("x0", 8, subregisters=(Reg("w0", 4, zero_extend_writes=True),)),
        Reg("x1", 8, subregisters=(Reg("w1", 4, zero_extend_writes=True),)),
        Reg("x2", 8, subregisters=(Reg("w2", 4, zero_extend_writes=True),)),
        Reg("x3", 8, subregisters=(Reg("w3", 4, zero_extend_writes=True),)),
        Reg("x4", 8, subregisters=(Reg("w4", 4, zero_extend_writes=True),)),
        Reg("x5", 8, subregisters=(Reg("w5", 4, zero_extend_writes=True),)),
        Reg("x6", 8, subregisters=(Reg("w6", 4, zero_extend_writes=True),)),
        Reg("x7", 8, subregisters=(Reg("w7", 4, zero_extend_writes=True),)),
        Reg("x8", 8, subregisters=(Reg("w8", 4, zero_extend_writes=True),)),
        Reg("x9", 8, subregisters=(Reg("w9", 4, zero_extend_writes=True),)),
        Reg("x10", 8, subregisters=(Reg("w10", 4, zero_extend_writes=True),)),
        Reg("x11", 8, subregisters=(Reg("w11", 4, zero_extend_writes=True),)),
        Reg("x12", 8, subregisters=(Reg("w12", 4, zero_extend_writes=True),)),
        Reg("x13", 8, subregisters=(Reg("w13", 4, zero_extend_writes=True),)),
        Reg("x14", 8, subregisters=(Reg("w14", 4, zero_extend_writes=True),)),
        Reg("x15", 8, subregisters=(Reg("w15", 4, zero_extend_writes=True),)),
        Reg("x16", 8, subregisters=(Reg("w16", 4, zero_extend_writes=True),)),
        Reg("x17", 8, subregisters=(Reg("w17", 4, zero_extend_writes=True),)),
        Reg("x18", 8, subregisters=(Reg("w18", 4, zero_extend_writes=True),)),
        Reg("x19", 8, subregisters=(Reg("w19", 4, zero_extend_writes=True),)),
        Reg("x20", 8, subregisters=(Reg("w20", 4, zero_extend_writes=True),)),
        Reg("x21", 8, subregisters=(Reg("w21", 4, zero_extend_writes=True),)),
        Reg("x22", 8, subregisters=(Reg("w22", 4, zero_extend_writes=True),)),
        Reg("x23", 8, subregisters=(Reg("w23", 4, zero_extend_writes=True),)),
        Reg("x24", 8, subregisters=(Reg("w24", 4, zero_extend_writes=True),)),
        Reg("x25", 8, subregisters=(Reg("w25", 4, zero_extend_writes=True),)),
        Reg("x26", 8, subregisters=(Reg("w26", 4, zero_extend_writes=True),)),
        Reg("x27", 8, subregisters=(Reg("w27", 4, zero_extend_writes=True),)),
        Reg("x28", 8, subregisters=(Reg("w28", 4, zero_extend_writes=True),)),
        Reg("x29", 8, subregisters=(Reg("w29", 4, zero_extend_writes=True),)),
    ),
    args=("x0", "x1", "x2", "x3"),
    retval="x0",
)


x86flags = {
    "eflags": BitFlags(
        [("CF", 0), ("PF", 2), ("AF", 4), ("ZF", 6), ("SF", 7), ("IF", 9), ("DF", 10), ("OF", 11)]
    )
}

amd64 = RegisterSet(
    pc=Reg("rip"),
    stack=Reg(
        "rsp",
        8,
        subregisters=(Reg("esp", 4, 0, zero_extend_writes=True), Reg("sp", 2, 0), Reg("spl", 1, 0)),
    ),
    frame=Reg(
        "rbp",
        8,
        subregisters=(Reg("ebp", 4, 0, zero_extend_writes=True), Reg("bp", 2, 0), Reg("bpl", 1, 0)),
    ),
    flags=x86flags,
    gpr=(
        Reg(
            "rax",
            8,
            subregisters=(
                Reg("eax", 4, 0, zero_extend_writes=True),
                Reg("ax", 2, 0),
                Reg("ah", 1, 1),
                Reg("al", 1, 0),
            ),
        ),
        Reg(
            "rbx",
            8,
            subregisters=(
                Reg("ebx", 4, 0, zero_extend_writes=True),
                Reg("bx", 2, 0),
                Reg("bh", 1, 1),
                Reg("bl", 1, 0),
            ),
        ),
        Reg(
            "rcx",
            8,
            subregisters=(
                Reg("ecx", 4, 0, zero_extend_writes=True),
                Reg("cx", 2, 0),
                Reg("ch", 1, 1),
                Reg("cl", 1, 0),
            ),
        ),
        Reg(
            "rdx",
            8,
            subregisters=(
                Reg("edx", 4, 0, zero_extend_writes=True),
                Reg("dx", 2, 0),
                Reg("dh", 1, 1),
                Reg("dl", 1, 0),
            ),
        ),
        Reg(
            "rdi",
            8,
            subregisters=(
                Reg("edi", 4, 0, zero_extend_writes=True),
                Reg("di", 2, 0),
                Reg("dil", 1, 0),
            ),
        ),
        Reg(
            "rsi",
            8,
            subregisters=(
                Reg("esi", 4, 0, zero_extend_writes=True),
                Reg("si", 2, 0),
                Reg("sil", 1, 0),
            ),
        ),
        Reg(
            "r8",
            8,
            subregisters=(
                Reg("r8d", 4, 0, zero_extend_writes=True),
                Reg("r8w", 2, 0),
                Reg("r8b", 1, 0),
            ),
        ),
        Reg(
            "r9",
            8,
            subregisters=(
                Reg("r9d", 4, 0, zero_extend_writes=True),
                Reg("r9w", 2, 0),
                Reg("r9b", 1, 0),
            ),
        ),
        Reg(
            "r10",
            8,
            subregisters=(
                Reg("r10d", 4, 0, zero_extend_writes=True),
                Reg("r10w", 2, 0),
                Reg("r10b", 1, 0),
            ),
        ),
        Reg(
            "r11",
            8,
            subregisters=(
                Reg("r11d", 4, 0, zero_extend_writes=True),
                Reg("r11w", 2, 0),
                Reg("r11b", 1, 0),
            ),
        ),
        Reg(
            "r12",
            8,
            subregisters=(
                Reg("r12d", 4, 0, zero_extend_writes=True),
                Reg("r12w", 2, 0),
                Reg("r12b", 1, 0),
            ),
        ),
        Reg(
            "r13",
            8,
            subregisters=(
                Reg("r13d", 4, 0, zero_extend_writes=True),
                Reg("r13w", 2, 0),
                Reg("r13b", 1, 0),
            ),
        ),
        Reg(
            "r14",
            8,
            subregisters=(
                Reg("r14d", 4, 0, zero_extend_writes=True),
                Reg("r14w", 2, 0),
                Reg("r14b", 1, 0),
            ),
        ),
        Reg(
            "r15",
            8,
            subregisters=(
                Reg("r15d", 4, 0, zero_extend_writes=True),
                Reg("r15w", 2, 0),
                Reg("r15b", 1, 0),
            ),
        ),
    ),
    misc=(
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "fsbase",
        "gsbase",
        "ip",
    ),
    args=("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    retval="rax",
)

i386 = RegisterSet(
    pc=Reg("eip"),
    stack=Reg("esp", 4, subregisters=(Reg("sp", 2, 0),)),
    frame=Reg("ebp", 4, subregisters=(Reg("bp", 2, 0),)),
    flags=x86flags,
    gpr=(
        Reg(
            "eax",
            4,
            subregisters=(Reg("ax", 2, 0), Reg("ah", 1, 1), Reg("al", 1, 0)),
        ),
        Reg(
            "ebx",
            4,
            subregisters=(Reg("bx", 2, 0), Reg("bh", 1, 1), Reg("bl", 1, 0)),
        ),
        Reg(
            "ecx",
            4,
            subregisters=(Reg("cx", 2, 0), Reg("ch", 1, 1), Reg("cl", 1, 0)),
        ),
        Reg(
            "edx",
            4,
            subregisters=(Reg("dx", 2, 0), Reg("dh", 1, 1), Reg("dl", 1, 0)),
        ),
        Reg(
            "edi",
            4,
            subregisters=(Reg("di", 2, 0),),
        ),
        Reg(
            "esi",
            4,
            subregisters=(Reg("si", 2, 0),),
        ),
    ),
    misc=(
        "cs",
        "ss",
        "ds",
        "es",
        "fs",
        "gs",
        "fsbase",
        "gsbase",
        "ip",
    ),
    retval="eax",
)


# http://math-atlas.sourceforge.net/devel/assembly/elfspec_ppc.pdf
# r0      Volatile register which may be modified during function linkage
# r1      Stack frame pointer, always valid
# r2      System-reserved register (points at GOT)
# r3-r4   Volatile registers used for parameter passing and return values
# r5-r10  Volatile registers used for parameter passing
# r11-r12 Volatile registers which may be modified during function linkage
# r13     Small data area pointer register (points to TLS)
# r14-r30 Registers used for local variables
# r31     Used for local variables or "environment pointers"
powerpc = RegisterSet(
    retaddr=(Reg("lr"),),
    flags={"msr": BitFlags(), "xer": BitFlags()},
    gpr=(
        Reg("r0"),
        Reg("r1"),
        Reg("r2"),
        Reg("r3"),
        Reg("r4"),
        Reg("r5"),
        Reg("r6"),
        Reg("r7"),
        Reg("r8"),
        Reg("r9"),
        Reg("r10"),
        Reg("r11"),
        Reg("r12"),
        Reg("r13"),
        Reg("r14"),
        Reg("r15"),
        Reg("r16"),
        Reg("r17"),
        Reg("r18"),
        Reg("r19"),
        Reg("r20"),
        Reg("r21"),
        Reg("r22"),
        Reg("r23"),
        Reg("r24"),
        Reg("r25"),
        Reg("r26"),
        Reg("r27"),
        Reg("r28"),
        Reg("r29"),
        Reg("r30"),
        Reg("r31"),
        Reg("cr"),
        Reg("ctr"),
    ),
    args=("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
    retval="r3",
)

# http://people.cs.clemson.edu/~mark/sparc/sparc_arch_desc.txt
# http://people.cs.clemson.edu/~mark/subroutines/sparc.html
# https://www.utdallas.edu/~edsha/security/sparcoverflow.htm
#
# http://people.cs.clemson.edu/~mark/sparc/assembly.txt
# ____________________________________
# %g0 == %r0  (always zero)           \
# %g1 == %r1                          | g stands for global
# ...                                 |
# %g7 == %r7                          |
# ____________________________________/
# %o0 == %r8                          \
# ...                                 | o stands for output (note: not 0)
# %o6 == %r14 == %sp (stack ptr)      |
# %o7 == %r15 == for return address   |
# ____________________________________/
# %l0 == %r16                         \
# ...                                 | l stands for local (note: not 1)
# %l7 == %r23                         |
# ____________________________________/
# %i0 == %r24                         \
# ...                                 | i stands for input
# %i6 == %r30 == %fp (frame ptr)      |
# %i7 == %r31 == for return address   |
# ____________________________________/

sparc = RegisterSet(
    stack=Reg("sp"),
    frame=Reg("fp"),
    retaddr=(Reg("i7"),),
    flags={"psr": BitFlags()},
    gpr=(
        Reg("g1"),
        Reg("g2"),
        Reg("g3"),
        Reg("g4"),
        Reg("g5"),
        Reg("g6"),
        Reg("g7"),
        Reg("o0"),
        Reg("o1"),
        Reg("o2"),
        Reg("o3"),
        Reg("o4"),
        Reg("o5"),
        Reg("o7"),
        Reg("l0"),
        Reg("l1"),
        Reg("l2"),
        Reg("l3"),
        Reg("l4"),
        Reg("l5"),
        Reg("l6"),
        Reg("l7"),
        Reg("i0"),
        Reg("i1"),
        Reg("i2"),
        Reg("i3"),
        Reg("i4"),
        Reg("i5"),
    ),
    args=("i0", "i1", "i2", "i3", "i4", "i5"),
    retval="o0",
)

# http://logos.cs.uic.edu/366/notes/mips%20quick%20tutorial.htm
# r0        => zero
# r1        => temporary
# r2-r3     => values
# r4-r7     => arguments
# r8-r15    => temporary
# r16-r23   => saved values
# r24-r25   => temporary
# r26-r27   => interrupt/trap handler
# r28       => global pointer
# r29       => stack pointer
# r30       => frame pointer
# r31       => return address
mips = RegisterSet(
    frame=Reg("fp"),
    retaddr=(Reg("ra"),),
    gpr=(
        Reg("v0"),
        Reg("v1"),
        Reg("a0"),
        Reg("a1"),
        Reg("a2"),
        Reg("a3"),
        Reg("t0"),
        Reg("t1"),
        Reg("t2"),
        Reg("t3"),
        Reg("t4"),
        Reg("t5"),
        Reg("t6"),
        Reg("t7"),
        Reg("t8"),
        Reg("t9"),
        Reg("s0"),
        Reg("s1"),
        Reg("s2"),
        Reg("s3"),
        Reg("s4"),
        Reg("s5"),
        Reg("s6"),
        Reg("s7"),
        Reg("s8"),
        Reg("gp"),
    ),
    args=("a0", "a1", "a2", "a3"),
    retval="v0",
)

# https://riscv.org/technical/specifications/
# Volume 1, Unprivileged Spec v. 20191213
# Chapter 25 - RISC-V Assembly Programmer’s Handbook
# x0        => zero   (Hard-wired zero)
# x1        => ra     (Return address)
# x2        => sp     (Stack pointer)
# x3        => gp     (Global pointer)
# x4        => tp     (Thread pointer)
# x5        => t0     (Temporary/alternate link register)
# x6–7      => t1–2   (Temporaries)
# x8        => s0/fp  (Saved register/frame pointer)
# x9        => s1     (Saved register)
# x10-11    => a0–1   (Function arguments/return values)
# x12–17    => a2–7   (Function arguments)
# x18–27    => s2–11  (Saved registers)
# x28–31    => t3–6   (Temporaries)
# f0–7      => ft0–7  (FP temporaries)
# f8–9      => fs0–1  (FP saved registers)
# f10–11    => fa0–1  (FP arguments/return values)
# f12–17    => fa2–7  (FP arguments)
# f18–27    => fs2–11 (FP saved registers)
# f28–31    => ft8–11 (FP temporaries)
riscv = RegisterSet(
    pc=Reg("pc"),
    stack=Reg("sp"),
    retaddr=(Reg("ra"),),
    gpr=(
        Reg("gp"),
        Reg("tp"),
        Reg("t0"),
        Reg("t1"),
        Reg("t2"),
        Reg("s0"),
        Reg("s1"),
        Reg("a0"),
        Reg("a1"),
        Reg("a2"),
        Reg("a3"),
        Reg("a4"),
        Reg("a5"),
        Reg("a6"),
        Reg("a7"),
        Reg("s2"),
        Reg("s3"),
        Reg("s4"),
        Reg("s5"),
        Reg("s6"),
        Reg("s7"),
        Reg("s8"),
        Reg("s9"),
        Reg("s10"),
        Reg("s11"),
        Reg("t3"),
        Reg("t4"),
        Reg("t5"),
        Reg("t6"),
    ),
    args=("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
    # TODO: make retval a tuple
    # a1 for second return value
    retval="a0",
)

# https://docs.kernel.org/arch/loongarch/introduction.html
loongarch64 = RegisterSet(
    pc=Reg("pc"),
    stack=Reg("sp"),
    frame=Reg("fp"),
    retaddr=(Reg("ra"),),
    gpr=(
        Reg("a0"),
        Reg("a1"),
        Reg("a2"),
        Reg("a3"),
        Reg("a4"),
        Reg("a5"),
        Reg("a6"),
        Reg("a7"),
        Reg("t0"),
        Reg("t1"),
        Reg("t2"),
        Reg("t3"),
        Reg("t4"),
        Reg("t5"),
        Reg("t6"),
        Reg("t7"),
        Reg("t8"),
        Reg("s0"),
        Reg("s1"),
        Reg("s2"),
        Reg("s3"),
        Reg("s4"),
        Reg("s5"),
        Reg("s6"),
        Reg("s7"),
        Reg("s8"),
    ),
    args=(
        "a0",
        "a1",
        "a2",
        "a3",
        "a4",
        "a5",
        "a6",
        "a7",
    ),
    # r21 stores "percpu base address", referred to as "u0" in the kernel
    misc=("tp", "r21"),
)

# https://refspecs.linuxfoundation.org/ELF/zSeries/lzsabi0_zSeries/x410.html
# Register name | Usage                          | Call effect
# --------------|--------------------------------|----------------
# r0            | General purpose               | Volatile
# r1            | General purpose               | Volatile
# r2            | Parameter passing and return  | Volatile
# r3, r4, r5    | Parameter passing             | Volatile
# r6            | Parameter passing             | Saved
# r7 - r11      | Local variables               | Saved
# r12           | Local variable, commonly used | Saved
#               | as GOT pointer                |
# r13           | Local variable, commonly used | Saved
#               | as Literal Pool pointer       |
# r14           | Return address                | Volatile
# r15           | Stack pointer                 | Saved
s390x = RegisterSet(
    pc=Reg("pc"),
    retaddr=(Reg("r14"),),
    stack=Reg("r15"),
    flags={"pswm": BitFlags()},
    gpr=(
        Reg("r0"),
        Reg("r1"),
        Reg("r2"),
        Reg("r3"),
        Reg("r4"),
        Reg("r5"),
        Reg("r6"),
        Reg("r7"),
        Reg("r8"),
        Reg("r9"),
        Reg("r10"),
        Reg("r11"),
        Reg("r12"),
        Reg("r13"),
    ),
    args=("r2", "r3", "r4", "r5", "r6"),
    retval="r2",
)

reg_sets: Dict[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, RegisterSet] = {
    "i386": i386,
    "i8086": i386,
    "x86-64": amd64,
    "rv32": riscv,
    "rv64": riscv,
    "mips": mips,
    "sparc": sparc,
    "arm": arm,
    "armcm": armcm,
    "aarch64": aarch64,
    "powerpc": powerpc,
    "loongarch64": loongarch64,
    "s390x": s390x,
}
