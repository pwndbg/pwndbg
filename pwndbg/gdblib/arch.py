from __future__ import annotations

from typing import Literal
from typing_extensions import override

import struct
from typing import Literal
from typing import Dict
from typing import Tuple
from typing import TypeVar
from typing import Type


from pwndbg.lib.abi import ABI, SyscallABI,DEFAULT_ABIS,SYSCALL_ABIS,SIGRETURN_ABIS
from pwndbg.lib.regs import RegisterSet

import gdb
import pwnlib

import pwndbg.gdblib
from pwndbg.gdblib import typeinfo
from pwndbg.lib.arch import Arch

# TODO: x86-64 needs to come before i386 in the current implementation, make
# this order-independent
ARCHS = (
    "x86-64",
    "i386",
    "aarch64",
    "mips",
    "powerpc",
    "sparc",
    "arm",
    "armcm",
    "riscv:rv32",
    "riscv:rv64",
    "riscv",
)


# mapping between gdb and pwntools arch names
pwnlib_archs_mapping = {
    "x86-64": "amd64",
    "i386": "i386",
    "aarch64": "aarch64",
    "mips": "mips",
    "powerpc": "powerpc",
    "sparc": "sparc",
    "arm": "arm",
    "iwmmxt": "arm",
    "armcm": "thumb",
    "rv32": "riscv32",
    "rv64": "riscv64",
}


def read_thumb_bit() -> int | None:
    """
    Return 0 or 1, representing the status of the Thumb bit in the current Arm architecture

    Return None if the Thumb bit is not relevent to the current architecture
    """
    if pwndbg.gdblib.arch.current == "arm":
        # When program initially starts, cpsr may not be readable
        if (cpsr := pwndbg.gdblib.regs.cpsr) is not None:
            return (cpsr >> 5) & 1
    elif pwndbg.gdblib.arch.current == "armcm":
        # ARM Cortex-M procesors only suport Thumb mode. However, there is still a bit
        # that represents the Thumb mode (which is currently architecturally defined to be 1)
        if (xpsr := pwndbg.gdblib.regs.xpsr) is not None:
            return (xpsr >> 24) & 1
    # AArch64 does not have a Thumb bit
    return None


def get_thumb_mode_string() -> Literal["arm", "thumb"] | None:
    thumb_bit = read_thumb_bit()
    return None if thumb_bit is None else "thumb" if thumb_bit == 1 else "arm"


# def update_arch_hook(arch: Architecture):
#     # This might be due to starting a new binary or connecting to another remote process.
#     # This function will will be pass ed the architecture
#     # The specific debugger (GDB/LLDB) will detect the arch
#     # and call this function appropriately
#     arch = architecture

ArchType = Literal["i386","x86-64","rv32","rv64","mips","sparc","arm","iwmmxt","armcm","aarch64","powerpc"]
EndianType = Literal["little","big"]

FMT_LITTLE_ENDIAN = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}
FMT_BIG_ENDIAN = {1: "B", 2: ">H", 4: ">I", 8: ">Q"}


class PwndbgArchitecture:

    # Registry of all instances
    arch_registry: Dict[ArchType, PwndbgArchitecture] = {}
    
    @staticmethod
    def get_arch(name: ArchType) -> PwndbgArchitecture:
        # If a custom class has not been registered for the architecture, use base implementation
        if name not in PwndbgArchitecture.arch_registry:
            PwndbgArchitecture.arch_registry[name] = PwndbgArchitecture(name)
        
        return PwndbgArchitecture.arch_registry[name]

    def __init__(self, name: ArchType) -> None:
        """
        Calling the constructor will register the class with global list of PwndbgArchitectures
        """
        if name is not None:
            self.arch_registry[name] = self

        self.name: ArchType = name
        self.current = self.name

        # We have to set some values by default
        # These will be set again by the code that detects the global architecture
        self.update(typeinfo.ptrsize, "little")
    
    def update(self, ptrsize: int, endian: EndianType) -> None:
        """
        While debugging a process, certain aspects of the architecture can change.

        In some cases, the architecture can change during a program,
        such as the early stages of a x86 bootloader (16-bit mode to 32-bit mode).
        Other architectures can change endianness dynamically.

        This function should be called when a change is detected.
        """
        self.endian: EndianType = endian

        # Pointer size in bytes
        self.ptrsize: int = ptrsize
        self.ptrbits: int = self.ptrsize * 8
        self.ptrmask: int = (1 << self.ptrbits) - 1

        # The following three variables are common defaults
        # But can be explicitely set if there is a special case
        # Is the syscall ABI non-standard? Just do pwndbg.arch.abi = ...

        abi_identifer = (self.ptrbits,self.name,"linux")
        self.abi: ABI | None = DEFAULT_ABIS.get(abi_identifer)
        self.syscall_abi: SyscallABI | None = SYSCALL_ABIS.get(abi_identifer)
        self.sigreturn_abi: SyscallABI | None = SIGRETURN_ABIS.get(abi_identifer)


        self.fmts: Dict[int, str] = FMT_LITTLE_ENDIAN if endian == "little" else FMT_BIG_ENDIAN
        self.fmt: str = self.fmts[self.ptrsize]

        if self.name == "arm" and self.endian == "big":
            self.qemu = "armeb"
        elif self.name == "mips" and self.endian == "little":
            self.qemu = "mipsel"
        else:
            self.qemu = self.name

    def pack(self, integer: int) -> bytes:
        return struct.pack(self.fmt, integer & self.ptrmask)

    def unpack(self, data: bytes) -> int:
        return struct.unpack(self.fmt, data)[0]

    def pack_size(self, integer: int, size: int) -> bytes:
        return struct.pack(self.fmts[size], integer & self.ptrmask)

    def unpack_size(self, data: bytes, size: int) -> int:
        return struct.unpack(self.fmts[size], data)[0]

    def read_thumb_bit(self) -> Literal[0,1]:
        return 0
    
class ArmArch(PwndbgArchitecture):

    def __init__(self) -> None:
        super().__init__("arm")

    @override
    def read_thumb_bit(self) -> Literal[0,1]:
        # When program initially starts, cpsr may not be readable
        if (cpsr := pwndbg.gdblib.regs.cpsr) is not None:
            return (cpsr >> 5) & 1
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
    def read_thumb_bit(self) -> Literal[0,1]:
        """
        On Cortex-M processors, the Thumb bit is architecturally defined to be 1.
        """
        return 1

# Register all the custom classes
ArmArch()
ArmCortexArch()



# arch = Arch("i386", typeinfo.ptrsize, "little")
arch = PwndbgArchitecture.get_arch("i386")

# name: str
# ptrsize: int
# ptrmask: int
# endian: Literal["little", "big"]


def _get_arch(ptrsize: int):
    not_exactly_arch = False

    if "little" in gdb.execute("show endian", to_string=True).lower():
        endian = "little"
    else:
        endian = "big"

    # Importing requires that `pwndbg.dbg` already be set up, so we have to do
    # it here, rather then on the top level.
    import pwndbg.gdblib.proc

    if pwndbg.gdblib.proc.alive:
        arch = gdb.newest_frame().architecture().name()
    else:
        arch = gdb.execute("show architecture", to_string=True).strip()
        not_exactly_arch = True

    # Below, we fix the fetched architecture
    for match in ARCHS:
        if match in arch:
            # Distinguish between Cortex-M and other ARM
            if match == "arm" and "-m" in arch:
                match = "armcm"
            elif match.startswith("riscv:"):
                match = match[6:]
            elif match == "riscv":
                # If GDB doesn't detect the width, it will just say `riscv`.
                match = "rv64"
            return match, ptrsize, endian

    if not_exactly_arch:
        raise RuntimeError(f"Could not deduce architecture from: {arch}")

    return arch, ptrsize, endian


def update() -> None:
    global arch
    arch_name, ptrsize, endian = _get_arch(typeinfo.ptrsize)

    if arch.name != arch_name:
        print(arch_name, "SWITCH")
        # The architecture has changed! Get the instance of the new class
        arch = PwndbgArchitecture.get_arch(arch_name)
    print(arch.name)
    # arch.update(arch_name, ptrsize, endian)
    arch.update(ptrsize, endian)
    
    pwnlib.context.context.arch = pwnlib_archs_mapping[arch_name]
    pwnlib.context.context.bits = ptrsize * 8
