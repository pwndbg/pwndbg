#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This file declares types and methods useful for enumerating
all of the address spaces and permissions of an ELF file in memory.

This is necessary for when access to /proc is restricted, or when
working on a BSD system which simply does not have /proc.
"""
from __future__ import print_function
import gdb
import os
import re
import subprocess
import tempfile

import gef.dt
import gef.memory

# ELF constants
PF_X, PF_W, PF_R = 1,2,4
ET_EXEC, ET_DYN  = 2,3

# In order for this file to work, we need to have symbols loaded
# in GDB for various ELF header types.
#
# We can simply create an object file and load its symbols (and types!)
# into our address space.  This should not pollute any actual symbols
# since we don't declare any functions, and load the object file at
# address zero.
tempdir = tempfile.gettempdir()
gef_elf = os.path.join(tempdir, 'gef-elf')
with open(gef_elf + '.c', 'w+') as f:
    f.write('''#include <elf.h>
Elf32_Ehdr a;
Elf64_Ehdr b;
Elf32_Shdr c;
Elf64_Shdr d;
Elf32_Phdr e;
Elf64_Phdr f;
''')
    f.flush()

subprocess.check_output('gcc -c -g %s.c -o %s.o' % (gef_elf, gef_elf), shell=True)

def load(pointer):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A sorted list of gef.memory.Page objects

    Example:

        >>> gef.elf.load(gdb.parse_and_eval('$pc'))
        [Page('400000-4ef000 r-xp 0'),
         Page('6ef000-6f0000 r--p ef000'),
         Page('6f0000-6ff000 rw-p f0000')]
        >>> gef.elf.load(0x7ffff77a2000)
        [Page('7ffff75e7000-7ffff77a2000 r-xp 0x1bb000 0'),
         Page('7ffff77a2000-7ffff79a2000 ---p 0x200000 1bb000'),
         Page('7ffff79a2000-7ffff79a6000 r--p 0x4000 1bb000'),
         Page('7ffff79a6000-7ffff79ad000 rw-p 0x7000 1bf000')]
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
    base = int(pointer) & ~(0xfff)
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

    # For each Program Header which would load data into our
    # address space, create a representation of each individual
    # page and its permissions.
    #
    # Entries are processed in-order so that later entries
    # which change page permissions (e.g. PT_GNU_RELRO) will
    # override their small subset of address space.
    pages = []
    for i in range(0, phnum):
        p_phdr = int(base + phoff + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)

        memsz   = int(p_phdr['p_memsz'])
        vaddr   = int(p_phdr['p_vaddr'])
        offset  = int(p_phdr['p_offset'])
        flags   = int(p_phdr['p_flags'])

        if not memsz:
            continue

        memsz += gef.memory.page_offset(vaddr)
        memsz  = gef.memory.page_size_align(memsz)
        vaddr  = gef.memory.page_align(vaddr)
        offset = gef.memory.page_align(offset)

        # For each page described by this program header
        for page_addr in range(vaddr, vaddr+memsz, gef.memory.PAGE_SIZE):
            if page_addr in pages:
                page = pages[pages.index(page_addr)]

                if page.flags & PF_W != flags & PF_W:
                    oldf = page.flags
                    page.flags = flags | (page.flags & PF_X)
            else:
                page = gef.memory.Page(page_addr, gef.memory.PAGE_SIZE, flags, offset + (page_addr-vaddr))
                pages.append(page)

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if ET_DYN == int(Elfhdr['e_type']):
        for page in pages:
            page.vaddr += base

    # Merge contiguous sections of memory together
    pages.sort()
    prev = pages[0]
    for page in list(pages[1:]):

        if (prev.flags & PF_W) == (page.flags & PF_W) and prev.vaddr+prev.memsz == page.vaddr:
            prev.memsz += page.memsz
            pages.remove(page)
        else:
            prev = page

    # Fill in any gaps with no-access pages.
    # This is what the linker does, and what all the '---p' pages are.
    gaps = []
    for i in range(len(pages)-1):
        a, b    = pages[i:i+2]
        a_end   = (a.vaddr + a.memsz)
        b_begin = b.vaddr
        if a_end != b_begin:
            gaps.append(gef.memory.Page(a_end, b_begin-a_end, 0, b.offset))

    pages.extend(gaps)
    pages.sort()
    return pages
