#
#  mayhem/datatypes/elf.py
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above
#    copyright notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the project nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
from __future__ import annotations

import ctypes
from typing import Dict
from typing import Optional
from typing import Union

import pwndbg.aglib.ctypes

Elf32_Addr = ctypes.c_uint32
Elf32_Half = ctypes.c_uint16
Elf32_Off = ctypes.c_uint32
Elf32_Sword = ctypes.c_int32
Elf32_Word = ctypes.c_uint32

Elf64_Addr = ctypes.c_uint64
Elf64_Half = ctypes.c_uint16
Elf64_SHalf = ctypes.c_int16
Elf64_Off = ctypes.c_uint64
Elf64_Sword = ctypes.c_int32
Elf64_Word = ctypes.c_uint32
Elf64_Xword = ctypes.c_uint64
Elf64_Sxword = ctypes.c_int64


# Copied from https://elixir.bootlin.com/glibc/glibc-2.40.9000/source/elf/elf.h#L1193
AT_CONSTANTS: Dict[int, str] = {
    0: "AT_NULL",  # End of vector
    1: "AT_IGNORE",  # Entry should be ignored
    2: "AT_EXECFD",  # File descriptor of program
    3: "AT_PHDR",  # Program headers for program
    4: "AT_PHENT",  # Size of program header entry
    5: "AT_PHNUM",  # Number of program headers
    6: "AT_PAGESZ",  # System page size
    7: "AT_BASE",  # Base address of interpreter
    8: "AT_FLAGS",  # Flags
    9: "AT_ENTRY",  # Entry point of program
    10: "AT_NOTELF",  # Program is not ELF
    11: "AT_UID",  # Real uid
    12: "AT_EUID",  # Effective uid
    13: "AT_GID",  # Real gid
    14: "AT_EGID",  # Effective gid
    15: "AT_PLATFORM",  # String identifying platform
    16: "AT_HWCAP",  # Machine-dependent hints about processor capabilities
    17: "AT_CLKTCK",  # Frequency of times()
    18: "AT_FPUCW",  # Used FPU control word
    19: "AT_DCACHEBSIZE",  # Data cache block size
    20: "AT_ICACHEBSIZE",  # Instruction cache block size
    21: "AT_UCACHEBSIZE",  # Unified cache block size
    22: "AT_IGNOREPPC",  # Entry should be ignored
    23: "AT_SECURE",  # Boolean, was exec setuid-like?
    24: "AT_BASE_PLATFORM",  # String identifying real platforms
    25: "AT_RANDOM",  # Address of 16 random bytes
    26: "AT_HWCAP2",  # More machine-dependent hints about processor capabilities
    27: "AT_RSEQ_FEATURE_SIZE",  # rseq supported feature size
    28: "AT_RSEQ_ALIGN",  # rseq allocation alignment
    29: "AT_HWCAP3",  # Extension of AT_HWCAP
    30: "AT_HWCAP4",  # Extension of AT_HWCAP
    31: "AT_EXECFN",  # Filename of executable
    32: "AT_SYSINFO",  # Pointer to the global system page used for system calls
    33: "AT_SYSINFO_EHDR",  # Header for sysinfo
    34: "AT_L1I_CACHESHAPE",  # Shape of L1 instruction cache
    35: "AT_L1D_CACHESHAPE",  # Shape of L1 data cache
    36: "AT_L2_CACHESHAPE",  # Shape of L2 cache
    37: "AT_L3_CACHESHAPE",  # Shape of L3 cache
    40: "AT_L1I_CACHESIZE",  # Size of L1 instruction cache
    41: "AT_L1I_CACHEGEOMETRY",  # Geometry of L1 instruction cache
    42: "AT_L1D_CACHESIZE",  # Size of L1 data cache
    43: "AT_L1D_CACHEGEOMETRY",  # Geometry of L1 data cache
    44: "AT_L2_CACHESIZE",  # Size of L2 cache
    45: "AT_L2_CACHEGEOMETRY",  # Geometry of L2 cache
    46: "AT_L3_CACHESIZE",  # Size of L3 cache
    47: "AT_L3_CACHEGEOMETRY",  # Geometry of L3 cache
    51: "AT_MINSIGSTKSZ",  # Stack needed for signal delivery
}

AT_CONSTANT_NAMES = {v: k for k, v in AT_CONSTANTS.items()}


class constants:
    EI_MAG0 = 0
    EI_MAG1 = 1
    EI_MAG2 = 2
    EI_MAG3 = 3
    EI_CLASS = 4
    EI_DATA = 5
    EI_VERSION = 6
    EI_OSABI = 7
    EI_ABIVERSION = 8
    EI_PAD = 9
    EI_NIDENT = 16

    ELFMAG0 = 0x7F
    ELFMAG1 = ord("E")
    ELFMAG2 = ord("L")
    ELFMAG3 = ord("F")

    ELFCLASSNONE = 0
    ELFCLASS32 = 1
    ELFCLASS64 = 2

    ELFDATANONE = 0
    ELFDATA2LSB = 1
    ELFDATA2MSB = 2

    # Legal values for Elf_Phdr.p_type (segment type).
    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7

    # Legal values for Elf_Ehdr.e_type (object file type).
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4

    # Legal values for Elf_Dyn.d_tag (dynamic entry type).
    DT_NULL = 0
    DT_NEEDED = 1
    DT_PLTRELSZ = 2
    DT_PLTGOT = 3
    DT_HASH = 4
    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_RELA = 7
    DT_RELASZ = 8
    DT_RELAENT = 9
    DT_STRSZ = 10
    DT_SYMENT = 11
    DT_INIT = 12
    DT_FINI = 13
    DT_SONAME = 14
    DT_RPATH = 15
    DT_SYMBOLIC = 16
    DT_REL = 17
    DT_RELSZ = 18
    DT_RELENT = 19
    DT_PLTREL = 20
    DT_DEBUG = 21
    DT_TEXTREL = 22
    DT_JMPREL = 23
    DT_ENCODING = 32

    # Legal values for Elf_Shdr.sh_type (section type).
    SHT_NULL = 0
    SHT_PROGBITS = 1
    SHT_SYMTAB = 2
    SHT_STRTAB = 3
    SHT_RELA = 4
    SHT_HASH = 5
    SHT_DYNAMIC = 6
    SHT_NOTE = 7
    SHT_NOBITS = 8
    SHT_REL = 9
    SHT_SHLIB = 10
    SHT_DYNSYM = 11
    SHT_NUM = 12

    # Legal values for ST_TYPE subfield of Elf_Sym.st_info (symbol type).
    STT_NOTYPE = 0
    STT_OBJECT = 1
    STT_FUNC = 2
    STT_SECTION = 3
    STT_FILE = 4
    STT_COMMON = 5
    STT_TLS = 6

    #
    # Notes used in ET_CORE. Architectures export some of the arch register sets
    # using the corresponding note types via the PTRACE_GETREGSET and
    # PTRACE_SETREGSET requests.
    #
    NT_PRSTATUS = 1
    NT_PRFPREG = 2
    NT_PRPSINFO = 3
    NT_TASKSTRUCT = 4
    NT_AUXV = 6
    #
    # Note to userspace developers: size of NT_SIGINFO note may increase
    # in the future to accommodate more fields, don't assume it is fixed!
    #
    NT_SIGINFO = 0x53494749
    NT_FILE = 0x46494C45
    NT_PRXFPREG = 0x46E62B7F
    NT_PPC_VMX = 0x100
    NT_PPC_SPE = 0x101
    NT_PPC_VSX = 0x102
    NT_386_TLS = 0x200
    NT_386_IOPERM = 0x201
    NT_X86_XSTATE = 0x202
    NT_S390_HIGH_GPRS = 0x300
    NT_S390_TIMER = 0x301
    NT_S390_TODCMP = 0x302
    NT_S390_TODPREG = 0x303
    NT_S390_CTRS = 0x304
    NT_S390_PREFIX = 0x305
    NT_S390_LAST_BREAK = 0x306
    NT_S390_SYSTEM_CALL = 0x307
    NT_S390_TDB = 0x308
    NT_ARM_VFP = 0x400
    NT_ARM_TLS = 0x401
    NT_ARM_HW_BREAK = 0x402
    NT_ARM_HW_WATCH = 0x403
    NT_METAG_CBUF = 0x500
    NT_METAG_RPIPE = 0x501
    NT_METAG_TLS = 0x502

    AT_NULL = 0
    AT_IGNORE = 1
    AT_EXECFD = 2
    AT_PHDR = 3
    AT_PHENT = 4
    AT_PHNUM = 5
    AT_PAGESZ = 6
    AT_BASE = 7
    AT_FLAGS = 8
    AT_ENTRY = 9
    AT_NOTELF = 10
    AT_UID = 11
    AT_EUID = 12
    AT_GID = 13
    AT_EGID = 14
    AT_PLATFORM = 15
    AT_HWCAP = 16
    AT_CLKTCK = 17
    AT_FPUCW = 18
    AT_DCACHEBSIZE = 19
    AT_ICACHEBSIZE = 20
    AT_UCACHEBSIZE = 21
    AT_IGNOREPPC = 22
    AT_SECURE = 23
    AT_BASE_PLATFORM = 24
    AT_RANDOM = 25
    AT_EXECFN = 31
    AT_SYSINFO = 32
    AT_SYSINFO_EHDR = 33
    AT_L1I_CACHESHAPE = 34
    AT_L1D_CACHESHAPE = 35
    AT_L2_CACHESHAPE = 36
    AT_L3_CACHESHAPE = 37


class Elf32_Ehdr(pwndbg.aglib.ctypes.Structure):
    _fields_ = [
        ("e_ident", (ctypes.c_ubyte * 16)),
        ("e_type", Elf32_Half),
        ("e_machine", Elf32_Half),
        ("e_version", Elf32_Word),
        ("e_entry", Elf32_Addr),
        ("e_phoff", Elf32_Off),
        ("e_shoff", Elf32_Off),
        ("e_flags", Elf32_Word),
        ("e_ehsize", Elf32_Half),
        ("e_phentsize", Elf32_Half),
        ("e_phnum", Elf32_Half),
        ("e_shentsize", Elf32_Half),
        ("e_shnum", Elf32_Half),
        ("e_shstrndx", Elf32_Half),
    ]


class Elf64_Ehdr(pwndbg.aglib.ctypes.Structure):
    _fields_ = [
        ("e_ident", (ctypes.c_ubyte * 16)),
        ("e_type", Elf64_Half),
        ("e_machine", Elf64_Half),
        ("e_version", Elf64_Word),
        ("e_entry", Elf64_Addr),
        ("e_phoff", Elf64_Off),
        ("e_shoff", Elf64_Off),
        ("e_flags", Elf64_Word),
        ("e_ehsize", Elf64_Half),
        ("e_phentsize", Elf64_Half),
        ("e_phnum", Elf64_Half),
        ("e_shentsize", Elf64_Half),
        ("e_shnum", Elf64_Half),
        ("e_shstrndx", Elf64_Half),
    ]


class Elf32_Phdr(pwndbg.aglib.ctypes.Structure):
    _fields_ = [
        ("p_type", Elf32_Word),
        ("p_offset", Elf32_Off),
        ("p_vaddr", Elf32_Addr),
        ("p_paddr", Elf32_Addr),
        ("p_filesz", Elf32_Word),
        ("p_memsz", Elf32_Word),
        ("p_flags", Elf32_Word),
        ("p_align", Elf32_Word),
    ]


class Elf64_Phdr(pwndbg.aglib.ctypes.Structure):
    _fields_ = [
        ("p_type", Elf64_Word),
        ("p_flags", Elf64_Word),
        ("p_offset", Elf64_Off),
        ("p_vaddr", Elf64_Addr),
        ("p_paddr", Elf64_Addr),
        ("p_filesz", Elf64_Xword),
        ("p_memsz", Elf64_Xword),
        ("p_align", Elf64_Xword),
    ]


class AUXV(Dict[str, Union[int, str]]):
    AT_PHDR: Optional[int]
    AT_BASE: Optional[int]
    AT_PLATFORM: Optional[str]
    AT_BASE_PLATFORM: Optional[str]
    AT_ENTRY: Optional[int]
    AT_RANDOM: Optional[int]
    AT_EXECFN: Optional[str]
    AT_SYSINFO: Optional[int]
    AT_SYSINFO_EHDR: Optional[int]

    def set(self, const: int, value: int) -> None:
        name = AT_CONSTANTS.get(const, "AT_UNKNOWN%i" % const)

        if name in ["AT_EXECFN", "AT_PLATFORM", "AT_BASE_PLATFORM"]:
            try:
                value = (
                    pwndbg.dbg.selected_inferior()
                    .create_value(value)
                    .cast(pwndbg.aglib.typeinfo.pchar)
                    .string()
                )
            except Exception:
                value = "couldnt read AUXV!"

        self[name] = value

    def __getattr__(self, attr: str) -> Optional[Union[int, str]]:
        if attr in AT_CONSTANT_NAMES:
            return self.get(attr)

        raise AttributeError("%r object has no attribute %r" % (self.__class__.__name__, attr))

    def __str__(self) -> str:
        return str({k: v for k, v in self.items() if v is not None})
