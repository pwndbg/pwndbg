#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ctypes
import sys

import six

import pwndbg.arch
import pwndbg.events

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


AT_CONSTANTS = {
    0 : 'AT_NULL',      # /* End of vector */
    1 : 'AT_IGNORE',    # /* Entry should be ignored */
    2 : 'AT_EXECFD',    # /* File descriptor of program */
    3 : 'AT_PHDR',      # /* Program headers for program */
    4 : 'AT_PHENT',     # /* Size of program header entry */
    5 : 'AT_PHNUM',     # /* Number of program headers */
    6 : 'AT_PAGESZ',    # /* System page size */
    7 : 'AT_BASE',      # /* Base address of interpreter */
    8 : 'AT_FLAGS',     # /* Flags */
    9 : 'AT_ENTRY',     # /* Entry point of program */
    10: 'AT_NOTELF',    # /* Program is not ELF */
    11: 'AT_UID',       # /* Real uid */
    12: 'AT_EUID',      # /* Effective uid */
    13: 'AT_GID',       # /* Real gid */
    14: 'AT_EGID',      # /* Effective gid */
    15: 'AT_PLATFORM',  # /* String identifying platform */
    16: 'AT_HWCAP',     # /* Machine dependent hints about processor capabilities */
    17: 'AT_CLKTCK',    # /* Frequency of times() */
    18: 'AT_FPUCW',
    19: 'AT_DCACHEBSIZE',
    20: 'AT_ICACHEBSIZE',
    21: 'AT_UCACHEBSIZE',
    22: 'AT_IGNOREPPC',
    23: 'AT_SECURE',
    24: 'AT_BASE_PLATFORM', # String identifying real platforms
    25: 'AT_RANDOM',    # Address of 16 random bytes
    31: 'AT_EXECFN',    # Filename of executable
    32: 'AT_SYSINFO',
    33: 'AT_SYSINFO_EHDR',
    34: 'AT_L1I_CACHESHAPE',
    35: 'AT_L1D_CACHESHAPE',
    36: 'AT_L2_CACHESHAPE',
    37: 'AT_L3_CACHESHAPE',
}

class constants:
    EI_MAG0                 = 0
    EI_MAG1                 = 1
    EI_MAG2                 = 2
    EI_MAG3                 = 3
    EI_CLASS                = 4
    EI_DATA                 = 5
    EI_VERSION              = 6
    EI_OSABI                = 7
    EI_ABIVERSION           = 8
    EI_PAD                  = 9
    EI_NIDENT               = 16

    ELFMAG0                 = 0x7f
    ELFMAG1                 = ord('E')
    ELFMAG2                 = ord('L')
    ELFMAG3                 = ord('F')

    ELFCLASSNONE            = 0
    ELFCLASS32              = 1
    ELFCLASS64              = 2

    ELFDATANONE             = 0
    ELFDATA2LSB             = 1
    ELFDATA2MSB             = 2

    # Legal values for Elf_Phdr.p_type (segment type).
    PT_NULL                 = 0
    PT_LOAD                 = 1
    PT_DYNAMIC              = 2
    PT_INTERP               = 3
    PT_NOTE                 = 4
    PT_SHLIB                = 5
    PT_PHDR                 = 6
    PT_TLS                  = 7

    # Legal values for Elf_Ehdr.e_type (object file type).
    ET_NONE                 = 0
    ET_REL                  = 1
    ET_EXEC                 = 2
    ET_DYN                  = 3
    ET_CORE                 = 4

    # Legal values for Elf_Dyn.d_tag (dynamic entry type).
    DT_NULL                 = 0
    DT_NEEDED               = 1
    DT_PLTRELSZ             = 2
    DT_PLTGOT               = 3
    DT_HASH                 = 4
    DT_STRTAB               = 5
    DT_SYMTAB               = 6
    DT_RELA                 = 7
    DT_RELASZ               = 8
    DT_RELAENT              = 9
    DT_STRSZ                = 10
    DT_SYMENT               = 11
    DT_INIT                 = 12
    DT_FINI                 = 13
    DT_SONAME               = 14
    DT_RPATH                = 15
    DT_SYMBOLIC             = 16
    DT_REL                  = 17
    DT_RELSZ                = 18
    DT_RELENT               = 19
    DT_PLTREL               = 20
    DT_DEBUG                = 21
    DT_TEXTREL              = 22
    DT_JMPREL               = 23
    DT_ENCODING             = 32

    # Legal values for Elf_Shdr.sh_type (section type).
    SHT_NULL                = 0
    SHT_PROGBITS            = 1
    SHT_SYMTAB              = 2
    SHT_STRTAB              = 3
    SHT_RELA                = 4
    SHT_HASH                = 5
    SHT_DYNAMIC             = 6
    SHT_NOTE                = 7
    SHT_NOBITS              = 8
    SHT_REL                 = 9
    SHT_SHLIB               = 10
    SHT_DYNSYM              = 11
    SHT_NUM                 = 12

    # Legal values for ST_TYPE subfield of Elf_Sym.st_info (symbol type).
    STT_NOTYPE              = 0
    STT_OBJECT              = 1
    STT_FUNC                = 2
    STT_SECTION             = 3
    STT_FILE                = 4
    STT_COMMON              = 5
    STT_TLS                 = 6

    #
    # Notes used in ET_CORE. Architectures export some of the arch register sets
    # using the corresponding note types via the PTRACE_GETREGSET and
    # PTRACE_SETREGSET requests.
    #
    NT_PRSTATUS             = 1
    NT_PRFPREG              = 2
    NT_PRPSINFO             = 3
    NT_TASKSTRUCT           = 4
    NT_AUXV                 = 6
    #
    # Note to userspace developers: size of NT_SIGINFO note may increase
    # in the future to accomodate more fields, don't assume it is fixed!
    #
    NT_SIGINFO              = 0x53494749
    NT_FILE                 = 0x46494c45
    NT_PRXFPREG             = 0x46e62b7f
    NT_PPC_VMX              = 0x100
    NT_PPC_SPE              = 0x101
    NT_PPC_VSX              = 0x102
    NT_386_TLS              = 0x200
    NT_386_IOPERM           = 0x201
    NT_X86_XSTATE           = 0x202
    NT_S390_HIGH_GPRS       = 0x300
    NT_S390_TIMER           = 0x301
    NT_S390_TODCMP          = 0x302
    NT_S390_TODPREG         = 0x303
    NT_S390_CTRS            = 0x304
    NT_S390_PREFIX          = 0x305
    NT_S390_LAST_BREAK      = 0x306
    NT_S390_SYSTEM_CALL     = 0x307
    NT_S390_TDB             = 0x308
    NT_ARM_VFP              = 0x400
    NT_ARM_TLS              = 0x401
    NT_ARM_HW_BREAK         = 0x402
    NT_ARM_HW_WATCH         = 0x403
    NT_METAG_CBUF           = 0x500
    NT_METAG_RPIPE          = 0x501
    NT_METAG_TLS            = 0x502

    AT_NULL                 = 0
    AT_IGNORE               = 1
    AT_EXECFD               = 2
    AT_PHDR                 = 3
    AT_PHENT                = 4
    AT_PHNUM                = 5
    AT_PAGESZ               = 6
    AT_BASE                 = 7
    AT_FLAGS                = 8
    AT_ENTRY                = 9
    AT_NOTELF               = 10
    AT_UID                  = 11
    AT_EUID                 = 12
    AT_GID                  = 13
    AT_EGID                 = 14
    AT_PLATFORM             = 15
    AT_HWCAP                = 16
    AT_CLKTCK               = 17
    AT_FPUCW                = 18
    AT_DCACHEBSIZE          = 19
    AT_ICACHEBSIZE          = 20
    AT_UCACHEBSIZE          = 21
    AT_IGNOREPPC            = 22
    AT_SECURE               = 23
    AT_BASE_PLATFORM        = 24
    AT_RANDOM               = 25
    AT_EXECFN               = 31
    AT_SYSINFO              = 32
    AT_SYSINFO_EHDR         = 33
    AT_L1I_CACHESHAPE       = 34
    AT_L1D_CACHESHAPE       = 35
    AT_L2_CACHESHAPE        = 36
    AT_L3_CACHESHAPE        = 37

endian_ctypes_struct = {
    'little': ctypes.LittleEndianStructure,
    'big': ctypes.BigEndianStructure
}

def _create_elf_ehdr_cls(bits, endian):
    if bits == 32:
        Half = Elf32_Half
        Word = Elf32_Word
        Addr = Elf32_Addr
        Off = Elf32_Off
    elif bits == 64:
        Half = Elf64_Half
        Word = Elf64_Word
        Addr = Elf64_Addr
        Off = Elf64_Off
    else:
        raise Exception('Unrecognized bits: {}'.format(bits))

    base = endian_ctypes_struct[endian]

    class Elf_Ehdr(base):
        _fields_ = [("e_ident", (ctypes.c_ubyte * 16)),
                    ("e_type", Half),
                    ("e_machine", Half),
                    ("e_version", Word),
                    ("e_entry", Addr),
                    ("e_phoff", Off),
                    ("e_shoff", Off),
                    ("e_flags", Word),
                    ("e_ehsize", Half),
                    ("e_phentsize", Half),
                    ("e_phnum", Half),
                    ("e_shentsize", Half),
                    ("e_shnum", Half),
                    ("e_shstrndx", Half),]

    Elf_Ehdr.__name__ = 'Elf{}_Ehdr_{}'.format(bits, endian.title())

    return Elf_Ehdr

Elf32_Ehdr_Big = _create_elf_ehdr_cls(32, 'big')
Elf32_Ehdr_Little = _create_elf_ehdr_cls(32, 'little')

Elf64_Ehdr_Big = _create_elf_ehdr_cls(64, 'big')
Elf64_Ehdr_Little = _create_elf_ehdr_cls(64, 'little')


def _create_elf_phdr_classes(endian):
    base = endian_ctypes_struct[endian]

    class Elf32_Phdr(base):
        _fields_ = [("p_type", Elf32_Word),
                    ("p_offset", Elf32_Off),
                    ("p_vaddr", Elf32_Addr),
                    ("p_paddr", Elf32_Addr),
                    ("p_filesz", Elf32_Word),
                    ("p_memsz", Elf32_Word),
                    ("p_flags", Elf32_Word),
                    ("p_align", Elf32_Word),]

    Elf32_Phdr.__name__ = 'Elf32_Phdr_{}'.format(endian.title())

    class Elf64_Phdr(base):
        _fields_ = [("p_type", Elf64_Word),
                    ("p_flags", Elf64_Word),
                    ("p_offset", Elf64_Off),
                    ("p_vaddr", Elf64_Addr),
                    ("p_paddr", Elf64_Addr),
                    ("p_filesz", Elf64_Xword),
                    ("p_memsz", Elf64_Xword),
                    ("p_align", Elf64_Xword),]

    Elf64_Phdr.__name__ = 'Elf64_Phdr_{}'.format(endian.title())

    return Elf32_Phdr, Elf64_Phdr

Elf32_Phdr_Big, Elf64_Phdr_Big = _create_elf_phdr_classes('big')
Elf32_Phdr_Little, Elf64_Phdr_Little = _create_elf_phdr_classes('little')


def get_ehdr_phdr(ptrsize, endian):
    bits = ptrsize*8
    endian = endian.title()

    Ehdr = 'Elf{}_Ehdr_{}'.format(bits, endian)
    Phdr = 'Elf{}_Phdr_{}'.format(bits, endian)
    g = globals()

    return g[Ehdr], g[Phdr]
