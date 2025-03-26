from __future__ import annotations

import struct
from typing import Dict
from typing import Literal
from typing import Tuple

import pwnlib
from capstone import CS_ARCH_ARM
from capstone import CS_ARCH_ARM64
from capstone import CS_ARCH_MIPS
from capstone import CS_ARCH_PPC
from capstone import CS_ARCH_RISCV
from capstone import CS_ARCH_SPARC
from capstone import CS_ARCH_X86
from capstone import CS_MODE_16
from capstone import CS_MODE_32
from capstone import CS_MODE_64
from capstone import CS_MODE_ARM
from capstone import CS_MODE_MCLASS
from capstone import CS_MODE_MIPS32
from capstone import CS_MODE_MIPS32R6
from capstone import CS_MODE_MIPS64
from capstone import CS_MODE_RISCV32
from capstone import CS_MODE_RISCV64
from capstone import CS_MODE_RISCVC
from capstone import CS_MODE_THUMB
from capstone import CS_MODE_V9
from typing_extensions import override

import pwndbg
import pwndbg.aglib
from pwndbg.aglib import typeinfo

# Uncommenting this create circular import
# from pwndbg.aglib.disasm import emulated_arm_mode_cache
from pwndbg.lib.abi import ABI
from pwndbg.lib.abi import DEFAULT_ABIS
from pwndbg.lib.abi import SIGRETURN_ABIS
from pwndbg.lib.abi import SYSCALL_ABIS
from pwndbg.lib.abi import SyscallABI
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
from pwndbg.lib.arch import PWNLIB_ARCH_MAPPINGS
from pwndbg.lib.arch import ArchDefinition
from pwndbg.lib.arch import Platform

EndianType = Literal["little", "big"]

FMT_LITTLE_ENDIAN = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
FMT_BIG_ENDIAN = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}


class PwndbgArchitecture(ArchDefinition):
    """
    This class defines the context of the currently debugged architecture as well as other related information of the platform.

    This includes the following information:
    - Capstone/Unicorn constants
    - ABI information
    """

    name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE
    name_raw: str  # The raw string returned by the debugger
    endian: EndianType
    ptrsize: int
    ptrbits: int
    ptrmask: int
    abi: ABI | None
    syscall_abi: SyscallABI | None
    sigreturn_abi: SyscallABI | None
    platform: Platform
    # environment

    registered_architectures: Dict[PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, PwndbgArchitecture] = {}

    @staticmethod
    def get_arch(name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> PwndbgArchitecture:
        if name not in PwndbgArchitecture.registered_architectures:
            raise NotImplementedError()
            # If a custom class has not been registered for the architecture, use base implementation
            # PwndbgArchitecture.registered_architectures[name] = PwndbgArchitecture(name)

        return PwndbgArchitecture.registered_architectures[name]

    def __init__(self, name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> None:
        """
        Calling the constructor will register the class with global list of PwndbgArchitectures
        """
        self.registered_architectures[name] = self

        self.name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE = name

        # We have to set some values by default
        # These will be set again by the code that detects the global architecture
        self.update(
            ArchDefinition(
                name=name,
                name_raw=name,
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
        self.name_raw = arch_definition.name_raw
        self.platform = arch_definition.platform

        self.endian: EndianType = arch_definition.endian

        # Pointer size in bytes
        self.ptrsize: int = arch_definition.ptrsize
        self.ptrbits: int = self.ptrsize * 8
        self.ptrmask: int = (1 << self.ptrbits) - 1

        # TODO - allow these to be overriden by other means

        default_abi_identifer = (self.ptrbits, self.name, "linux")

        self.abi = DEFAULT_ABIS.get(default_abi_identifer)
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

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        """
        Return tuple of (CAPSTONE ARCH, CAPSTONE MODE) used to instantiate the Capstone disassembler for this architecture.
        """
        return (None, None)

    def read_thumb_bit(self) -> Literal[0, 1, None]:
        """
        Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

        Return None if the Thumb bit is not relevent to the current architecture
        """
        return None


class AMD64Arch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("x86-64")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_64)


class i386Arch(PwndbgArchitecture):
    """
    32-bit mode x86
    """

    def __init__(self) -> None:
        super().__init__("i386")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_32)


class i8086Arch(PwndbgArchitecture):
    """
    16-bit mode x86
    """

    def __init__(self) -> None:
        super().__init__("i8086")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_X86, CS_MODE_16)


class ArmArch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("arm")

    @override
    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        thumb_mode = pwndbg.aglib.disasm.emulated_arm_mode_cache[address]
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
    def __init__(self) -> None:
        super().__init__("aarch64")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_ARM64, CS_MODE_ARM)


class PowerPCArch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("powerpc")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        # TODO - what about 32-bit powerpc?
        return (CS_ARCH_PPC, CS_MODE_64)


class SparcArch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("sparc")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        if pwndbg.dbg.is_gdblib_available() and "v9" in self.name_raw:
            mode = CS_MODE_V9
        else:
            # The ptrsize base modes cause capstone.CsError: Invalid mode (CS_ERR_MODE)
            mode = 0

        return (CS_ARCH_SPARC, mode)


class RISCV32Arch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("rv32")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_RISCV, CS_MODE_RISCV32 | CS_MODE_RISCVC)


class RISCV64Arch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("rv64")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        return (CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCVC)


class MipsArch(PwndbgArchitecture):
    def __init__(self) -> None:
        super().__init__("mips")

    def get_capstone_constants(self, address: int) -> Tuple[int, int]:
        # TODO - Capstone v6 increased the number of MIPS constants
        if pwndbg.dbg.is_gdblib_available() and "isa32r6" in self.name_raw:
            extra = CS_MODE_MIPS32R6
        elif self.ptrsize == 64:
            extra = CS_MODE_MIPS64
        else:
            extra = CS_MODE_MIPS32

        return (CS_ARCH_MIPS, extra)


# Register the architecture classes
AMD64Arch()
i386Arch()
i8086Arch()
ArmArch()
ArmCortexArch()
AArch64Arch()
PowerPCArch()
SparcArch()
RISCV32Arch()
RISCV64Arch()
MipsArch()


def get_thumb_mode_string() -> Literal["arm", "thumb"] | None:
    thumb_bit = pwndbg.aglib.arch.read_thumb_bit()
    return None if thumb_bit is None else "thumb" if thumb_bit == 1 else "arm"


def update() -> None:
    a = pwndbg.dbg.selected_inferior().arch()

    pwnlib.context.context.arch = PWNLIB_ARCH_MAPPINGS.get(a.name, "none")
    pwnlib.context.context.bits = a.ptrsize * 8

    if a.name != pwndbg.aglib.arch.name:
        pwndbg_arch = PwndbgArchitecture.get_arch(a.name)
        pwndbg.aglib.set_arch(pwndbg_arch)

    pwndbg.aglib.arch.update(a)
