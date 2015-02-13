#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import gdb
import os
import re
import subprocess
import tempfile

import gef.dt
import gef.memory

"""
Because we may not have access to /proc for a multitude
of reasons, it helps to be able to parse out a little
bit of information from ELF files.

Instead of manually parsing things out, we can just load
types via an object file.
"""

tempdir = tempfile.gettempdir()
gef_elf = os.path.join(tempdir, 'gef-elf')
with open(gef_elf + '.c', 'w+') as f:
    f.write('''#include <elf.h>

void foo() {
    Elf32_Ehdr a;
    Elf64_Ehdr b;
    Elf32_Shdr c;
    Elf64_Shdr d;
    Elf32_Phdr e;
    Elf64_Phdr f;
}
''')
    f.flush()

PT_NULL, PT_LOAD = 0,1
PT_GNU_RELRO     = 0x6474e552
PF_X, PF_W, PF_R = 1,2,4
ET_EXEC, ET_DYN  = 2,3
PAGE_SIZE        = 0x1000

subprocess.check_output('gcc -c -g %s.c -o %s.o' % (gef_elf, gef_elf), shell=True)

class MemoryPage(object):
    start = 0
    size  = 0
    flags  = 0
    offset = 0
    permstr = 0
    def __init__(self, start, size, flags, offset):
        self.vaddr   = start
        self.memsz    = size
        self.flags    = flags
        self.offset  = offset
    @property
    def permstr(self):
        flags = self.flags
        return ''.join(['r' if flags & PF_R else '-'
                        'w' if flags & PF_W else '-'
                        'x' if flags & PF_X else '-'])
    def __str__(self):
        return "%x-%x %s %x" % (self.vaddr, self.vaddr+self.memsz, self.permstr, self.offset)
    def __repr__(self):
        return "MemoryPage(%r)" % self.__str__()
    def __contains__(self, a):
        return self.vaddr-1 < a < (self.vaddr + self.memsz)
    def __lt__(self, other):
        if isinstance(other, MemoryPage): other = other.vaddr
        return self.vaddr < other

def find_sections(pointer):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A sorted list of MemoryPage objects

    Example:

        >>> gef.elf.ELF(int(gdb.parse_and_eval('$pc')))
        [MemoryPage('400000-4ef000 r-x 0'),
         MemoryPage('6ef000-6f0000 r-- ef000'),
         MemoryPage('6f0000-6ff000 rw- f0000')]
    """
    gdb.execute('add-symbol-file %s.o 0' % gef_elf, from_tty=False, to_string=True)

    Elf32_Ehdr = gdb.lookup_type('Elf32_Ehdr')
    Elf64_Ehdr = gdb.lookup_type('Elf64_Ehdr')
    Elf32_Shdr = gdb.lookup_type('Elf32_Shdr')
    Elf64_Shdr = gdb.lookup_type('Elf64_Shdr')
    Elf32_Phdr = gdb.lookup_type('Elf32_Phdr')
    Elf64_Phdr = gdb.lookup_type('Elf64_Phdr')

    # Align down to a page boundary, and scan until we find
    # the ELF header.
    base = pointer & ~(0xfff)
    data = gef.memory.read(base, 4)
    while data != b'\x7FELF':
        base -= 0x1000
        data = gef.memory.read(base, 4)

    # Determine whether it's 32- or 64-bit
    ei_class = gef.memory.byte(base+4)

    # Find out where the section headers start
    EhdrType = { 1: Elf32_Ehdr, 2: Elf64_Ehdr }[ei_class]
    ShdrType = { 1: Elf32_Shdr, 2: Elf64_Shdr }[ei_class]
    PhdrType = { 1: Elf32_Phdr, 2: Elf64_Phdr }[ei_class]

    Elfhdr    = gef.memory.poi(EhdrType, base)
    phnum     = int(Elfhdr['e_phnum'])
    phoff     = int(Elfhdr['e_phoff'])
    phentsize = int(Elfhdr['e_phentsize'])

    print(gef.dt.dt(obj=Elfhdr))

    # Find all PT_LOAD headers, and register all of the pages they touch
    sections = []
    for i in range(0, phnum):
        p_phdr = int(base + phoff + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)

        if p_phdr['p_type'] != PT_LOAD:
            continue

        vaddr   = int(p_phdr['p_vaddr'])
        memsz   = int(p_phdr['p_memsz'])
        offset  = int(p_phdr['p_offset'])
        flags   = int(p_phdr['p_flags'])

        vaddr  = gef.memory.page_align(vaddr)
        memsz  = gef.memory.page_size_align(memsz)
        offset = gef.memory.page_align(offset)

        for page in (vaddr, vaddr+memsz, gef.memory.PAGE_SIZE)
            section = MemoryPage(vaddr, memsz, flags, offset)
            sections.append(section)

    # Find all other PHDRs which modify permissions, e.g. relro
    # and split them off into their own.
    for i in range(0, phnum):
        p_phdr = int(base + phoff + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)

        if p_phdr['p_type'] in (PT_NULL, PT_LOAD):
            continue

        vaddr   = int(p_phdr['p_vaddr'])
        memsz   = int(p_phdr['p_memsz'])
        offset  = int(p_phdr['p_offset'])
        flags   = int(p_phdr['p_flags'])

        if memsz == 0:
            continue

        # Find the pages this touches, and update them
        for section in sections:
            if vaddr <= section.start < vaddr+memsz:
               section.flags = flags


        # The only permissions changes that the ELF loader sets
        # will be to remove the write flag.
        # It doesn't appear to ever remove the execute flag.
        if (section.flags & PF_W) == (flags & PF_W):
            print("Ignoring...")
            print(gef.dt.dt(obj=p_phdr))
            print()
            continue

        print("Splitting with...")
        print(gef.dt.dt(obj=p_phdr))

        sections.append(MemoryPage(vaddr, memsz, flags, offset))

        # Break off the front
        if section.vaddr == vaddr:
            section.vaddr   += memsz
            section.memsz   -= memsz
            section.offset  += memsz

        # Break off the back
        elif section.vaddr+section.memsz != vaddr+memsz:
            section.memsz  -= memsz
            section.offset += memsz

        # Take a chunk out of the middle
        else:
            raise NotImplementedError("Uh oh")

    # Adjust everything down to page boundaries
    for section in sections:
        section.vaddr  = gef.memory.align_down(section.vaddr, 0x1000)
        section.memsz  = gef.memory.align_up(section.memsz, 0x1000)
        section.offset = gef.memory.align_down(section.offset, 0x1000)

        # Adjust against the base address that we discovered
        # for binaries that are relocatable / type DYN.
        if ET_DYN == int(Elfhdr['e_type']):
            section.vaddr += base

    sections.sort()
    return sections
