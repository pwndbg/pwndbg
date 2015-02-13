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
    vaddr = 0
    memsz  = 0
    flags  = 0
    offset = 0
    def __init__(self, start, size, flags, offset):
        self.vaddr   = start
        self.memsz    = size
        self.flags    = flags
        self.offset  = offset
    @property
    def permstr(self):
        flags = self.flags
        return ''.join(['r' if flags & PF_R else '-',
                        'w' if flags & PF_W else '-',
                        'x' if flags & PF_X else '-',
                        'p'])
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
    pages = []
    for i in range(0, phnum):
        p_phdr = int(base + phoff + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)

        if p_phdr['p_type'] != PT_LOAD:
            continue

        print(gef.dt.dt(obj=p_phdr))

        vaddr   = int(p_phdr['p_vaddr'])
        memsz   = int(p_phdr['p_memsz'])
        offset  = int(p_phdr['p_offset'])
        flags   = int(p_phdr['p_flags'])

        vaddr  = gef.memory.page_align(vaddr)
        memsz  = gef.memory.page_size_align(memsz)
        offset = gef.memory.page_align(offset)


        print("%#x %#x %#x", vaddr, vaddr+memsz, gef.memory.PAGE_SIZE)
        for page_addr in range(vaddr, vaddr+memsz, gef.memory.PAGE_SIZE):
            page = MemoryPage(page_addr, gef.memory.PAGE_SIZE, flags, offset + (page_addr-vaddr))
            print(page)
            pages.append(page)

    # Logic past here expects sections to be non-empty
    if not pages:
        return []

    # Find all other PHDRs which modify permissions, e.g. relro
    # and update the page permissions accordingly.
    for i in range(0, phnum):
        p_phdr = int(base + phoff + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)

        if p_phdr['p_type'] in (PT_NULL, PT_LOAD):
            continue

        vaddr   = int(p_phdr['p_vaddr'])
        memsz   = int(p_phdr['p_memsz'])
        flags   = int(p_phdr['p_flags'])

        vaddr  = gef.memory.page_align(vaddr)
        memsz  = gef.memory.page_size_align(memsz)

        if memsz == 0:
            continue

        # Find the pages this touches, and update them
        # It seems that the PF_X flag is never actively removed.
        for page_addr in range(vaddr, vaddr+memsz, gef.memory.PAGE_SIZE):
            for page in pages:
                if page_addr == page.vaddr:
                    if page.flags & PF_W == flags & PF_W:
                        print("Skipping", page_addr)
                    else:
                        oldf = page.flags
                        page.flags = flags | (page.flags & PF_X)
                        print("Updated", p_phdr['p_type'], oldf, page)

    # Collect contiguous sections of memory together
    last = pages[0]
    for page in list(pages[1:]):
        if (last.flags & PF_W) == (page.flags & PF_W) and last.vaddr+last.memsz == page.vaddr:
            last.memsz += page.memsz
            pages.remove(page)
        else:
            last = page

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if ET_DYN == int(Elfhdr['e_type']):
        for page in pages:
            page.vaddr += base

    pages.sort()
    return pages
