from __future__ import annotations

import struct
from typing import Dict
from typing import List
from typing import Literal
from typing import Tuple

import pwnlib
from capstone import CS_ARCH_AARCH64
from capstone import CS_ARCH_ARM
from capstone import CS_ARCH_LOONGARCH
from capstone import CS_ARCH_MIPS
from capstone import CS_ARCH_PPC
from capstone import CS_ARCH_RISCV
from capstone import CS_ARCH_SPARC
from capstone import CS_ARCH_SYSTEMZ
from capstone import CS_ARCH_X86
from capstone import CS_MODE_16
from capstone import CS_MODE_32
from capstone import CS_MODE_64
from capstone import CS_MODE_ARM
from capstone import CS_MODE_LOONGARCH64
from capstone import CS_MODE_MCLASS
from capstone import CS_MODE_MIPS32
from capstone import CS_MODE_MIPS64
from capstone import CS_MODE_RISCV32
from capstone import CS_MODE_RISCV64
from capstone import CS_MODE_RISCVC
from capstone import CS_MODE_THUMB
from capstone import CS_MODE_V9
from typing_extensions import override

import pwndbg
import pwndbg.aglib
import pwndbg.aglib.disasm
from pwndbg.aglib import typeinfo
from pwndbg.lib.abi import ABI
from pwndbg.lib.abi import DEFAULT_ABIS
from pwndbg.lib.abi import SIGRETURN_ABIS
from pwndbg.lib.abi import SYSCALL_ABIS
from pwndbg.lib.abi import SyscallABI
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import PWNLIB_ARCH_MAPPINGS
from pwndbg.lib.arch import ArchAttribute
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform

EndianType = Literal["little", "big"]

FMT_LITTLE_ENDIAN = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
FMT_BIG_ENDIAN = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}


registered_architectures: Dict[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, PwndbgArchitecture] = {}


def register_arch(arch: PwndbgArchitecture):
    registered_architectures[arch.name] = arch


def get_pwndbg_architecture(name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> PwndbgArchitecture | None:
    if name not in registered_architectures:
        return None

    return registered_architectures[name]


class PwndbgArchitecture(ArchDefinition):
    """
    This class defines the context of the currently debugged architecture as well as other related information of the platform.

    This includes the following information:
    - Capstone/Unicorn constants
    - ABI information
    """

    ### All subclasses must provide values for the following attributes

    max_instruction_size: int

    ###

    name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
    endian: EndianType
    ptrsize: int
    """Pointer size in bytes"""
    ptrbits: int
    """Pointer size in bits"""
    ptrmask: int
    function_abi: ABI | None
    syscall_abi: SyscallABI | None
    sigreturn_abi: SyscallABI | None
    platform: Platform
    attributes: List[ArchAttribute]

    fmts: Dict[int, str]
    fmt: str

    def __init__(self, name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> None:
        self.name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE = name

        # We have to set some values by default
        # These will be set again by the code that detects the global architecture
        self.update(
            ArchDefinition(
                name=name,
                ptrsize=typeinfo.ptrsize,
                endian="little",
                platform=Platform.LINUX,
            )
        )

    def update(self, arch_definition: ArchDefinition) -> None:
        """
        While debugging a process, certain aspects of the architecture can change.

        For example:
        - Some architectures can change endianness dynamically.
        """
        self.platform = arch_definition.platform
        self.attributes = arch_definition.attributes

        self.endian: EndianType = arch_definition.endian

        self.ptrsize: int = arch_definition.ptrsize
        self.ptrbits: int = self.ptrsize * 8
        self.ptrmask: int = (1 << self.ptrbits) - 1

        default_abi_identifer = (self.ptrbits, self.name, "linux")

        self.function_abi = DEFAULT_ABIS.get(default_abi_identifer)
        self.syscall_abi = SYSCALL_ABIS.get(default_abi_identifer)
        self.sigreturn_abi = SIGRETURN_ABIS.get(default_abi_identifer)

        self.fmts: Dict[int, str] = FMT_LITTLE_ENDIAN if self.endian == "little" else FMT_BIG_ENDIAN
        self.fmt: str = self.fmts[self.ptrsize]

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]

    def pack_size(self, integer: int, size: int) -> bytes:
        return struct.pack(self.fmts[size], integer & self.ptrmask)

    def unpack_size(self, data: bytes, size: int) -> int:
        return struct.unpack(self.fmts[size], data)[0]

    def get_capstone_constants(self, address: int) -> Tuple[int, int] | None:
        """
        Return tuple of (CAPSTONE ARCH, CAPSTONE MODE) used to instantiate the Capstone disassembler for this architecture.
        """
        return None

    def read_thumb_bit(self) -> Literal[0, 1, None]:
        """
        Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

        Return None if the Thumb bit is not relevent to the current architecture
        """
        return None


class AMD64Arch(PwndbgArchitecture):
    max_instruction_size = 16

    def __init__(self) -> None:
        super().__init__("x86-64")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_64)


class i386Arch(PwndbgArchitecture):
    """
    32-bit mode x86
    """

    max_instruction_size = 16

    def __init__(self) -> None:
        super().__init__("i386")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_32)


class i8086Arch(PwndbgArchitecture):
    """
    16-bit mode x86
    """

    max_instruction_size = 16

    def __init__(self) -> None:
        super().__init__("i8086")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_16)


class ArmArch(PwndbgArchitecture):
    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("arm")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        thumb_mode = pwndbg.aglib.disasm.disassembly.emulated_arm_mode_cache[address]
        if thumb_mode is None:
            thumb_mode = self.read_thumb_bit()
        mode = CS_MODE_THUMB if thumb_mode else CS_MODE_ARM

        return (CS_ARCH_ARM, mode)

    @override
    def read_thumb_bit(self) -> Literal[0, 1]:
        # When program initially starts, cpsr may not be readable
        if (cpsr := pwndbg.aglib.regs.cpsr) is not None:
            return (cpsr >> 5) & 1  # type: ignore[return-value]

        return 0


class ArmCortexArch(PwndbgArchitecture):
    """
    Cortex-M processors run the M-profile Arm architecture.
    This architecture is prevalent in bare-metal/embedded systems that lack operating systems.
    Only Thumb-2 instructions are supported, and the Thumb bit is always 1.
    """

    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("armcm")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_ARM, CS_MODE_MCLASS | CS_MODE_THUMB)

    @override
    def read_thumb_bit(self) -> Literal[0, 1]:
        """
        On Cortex-M processors, the Thumb bit is architecturally defined to be 1.

        This is the (xpsr >> 24) & 1, which is always 1.
        """
        return 1


class AArch64Arch(PwndbgArchitecture):
    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("aarch64")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_AARCH64, CS_MODE_ARM)


class PowerPCArch(PwndbgArchitecture):
    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("powerpc")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_PPC, CS_MODE_64)


class SparcArch(PwndbgArchitecture):
    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("sparc")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        mode = CS_MODE_V9 if self.ptrsize == 8 else 0
        return (CS_ARCH_SPARC, mode)


class RISCV32Arch(PwndbgArchitecture):
    max_instruction_size = 22

    def __init__(self) -> None:
        super().__init__("rv32")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


class RISCV64Arch(PwndbgArchitecture):
    max_instruction_size = 22

    def __init__(self) -> None:
        super().__init__("rv64")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)


class MipsArch(PwndbgArchitecture):
    max_instruction_size = 8

    def __init__(self) -> None:
        super().__init__("mips")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        extra = 0
        for attribute in self.attributes:
            if attribute.cs_mode is not None:
                extra |= attribute.cs_mode

        if extra == 0:
            extra = CS_MODE_MIPS64 if self.ptrsize == 8 else CS_MODE_MIPS32

        return (CS_ARCH_MIPS, extra)


class Loongarch64Arch(PwndbgArchitecture):
    max_instruction_size = 4

    def __init__(self) -> None:
        super().__init__("loongarch64")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_LOONGARCH, CS_MODE_LOONGARCH64)


class S390xArch(PwndbgArchitecture):
    max_instruction_size = 6

    def __init__(self) -> None:
        super().__init__("s390x")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_SYSTEMZ, 0)


# Register the architecture classes
all_arches = [
    AMD64Arch(),
    i386Arch(),
    i8086Arch(),
    ArmArch(),
    ArmCortexArch(),
    AArch64Arch(),
    PowerPCArch(),
    SparcArch(),
    RISCV32Arch(),
    RISCV64Arch(),
    MipsArch(),
    Loongarch64Arch(),
    S390xArch(),
]

for arch in all_arches:
    register_arch(arch)


def get_thumb_mode_string() -> Literal["arm", "thumb"] | None:
    thumb_bit = pwndbg.aglib.arch.read_thumb_bit()
    return None if thumb_bit is None else "thumb" if thumb_bit == 1 else "arm"


def update() -> None:
    a = pwndbg.dbg.selected_inferior().arch()

    pwnlib.context.context.arch = PWNLIB_ARCH_MAPPINGS.get(a.name, "none")
    pwnlib.context.context.bits = a.ptrsize * 8

    if a.name != pwndbg.aglib.arch.name:
        pwndbg_arch = get_pwndbg_architecture(a.name)
        if pwndbg_arch is None:
            raise pwndbg.dbg_mod.Error(
                f"Unsupported architecture: {a.name}. "
                f"It may be that Pwndbg is not correctly categorizing the architecture. "
                f"Please file a bug report. "
            )
        pwndbg.aglib.set_arch(pwndbg_arch)

    pwndbg.aglib.arch.update(a)
