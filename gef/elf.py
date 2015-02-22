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

import gef.events
import gef.info
import gef.memory
import gef.memoize
import gef.stack
import gef.auxv

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
Elf32_Phdr e;
Elf64_Phdr f;
''')
    f.flush()

subprocess.check_output('gcc -c -g %s.c -o %s.o' % (gef_elf, gef_elf), shell=True)

@gef.memoize.reset_on_exit
def exe():
    """
    Return a loaded ELF header object pointing to the Ehdr of the
    main executable.
    """
    elf = None
    ptr = entry()
    return load(ptr)

@gef.memoize.reset_on_exit
def entry():
    """
    Return the address of the entry point for the main executable.
    """
    entry = gef.auxv.get().AT_ENTRY
    if entry:
        return entry

    # Looking for this line:
    # Entry point: 0x400090
    for line in gef.info.files().splitlines():
        if "Entry point" in line:
            return int(line.split()[-1], 16)

    # Try common names
    for name in ['_start', 'start', '__start', 'main']:
        try:
            return int(gdb.parse_and_eval(name))
        except gdb.error:
            pass

    # Can't find it, give up.
    return 0


def load(pointer):
    return get_ehdr(pointer)[1]

def get_ehdr(pointer):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A tuple containing (ei_class, gdb.Value).
        The gdb.Value object has type of either Elf32_Ehdr or Elf64_Ehdr.

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

    # Align down to a page boundary, and scan until we find
    # the ELF header.
    base = gef.memory.page_align(pointer)
    data = gef.memory.read(base, 4)

    try:
        while data != b'\x7FELF':
            base -= gef.memory.PAGE_SIZE
            data = gef.memory.read(base, 4)
    except gdb.MemoryError:
        return None, None

    # Determine whether it's 32- or 64-bit
    ei_class = gef.memory.byte(base+4)

    # Find out where the section headers start
    EhdrType = { 1: Elf32_Ehdr, 2: Elf64_Ehdr }[ei_class]
    Elfhdr   = gef.memory.poi(EhdrType, base)
    return ei_class, Elfhdr

def get_phdrs(pointer):
    """
    Returns a tuple containing (phnum, phentsize, gdb.Value),
    where the gdb.Value object is an ELF Program Header with
    the architecture-appropriate structure type.
    """
    ei_class, Elfhdr = get_ehdr(pointer)

    if Elfhdr is None:
        return (0, 0, None)

    Elf32_Phdr = gdb.lookup_type('Elf32_Phdr')
    Elf64_Phdr = gdb.lookup_type('Elf64_Phdr')
    PhdrType   = { 1: Elf32_Phdr, 2: Elf64_Phdr }[ei_class]

    phnum     = int(Elfhdr['e_phnum'])
    phoff     = int(Elfhdr['e_phoff'])
    phentsize = int(Elfhdr['e_phentsize'])

    x = (phnum, phentsize, gef.memory.poi(PhdrType, int(Elfhdr.address) + phoff))
    return x

def iter_phdrs(ehdr):
    phnum, phentsize, phdr = get_phdrs(int(ehdr.address))

    if not phdr:
        return []

    first_phdr = int(phdr.address)
    PhdrType   = phdr.type

    for i in range(0, phnum):
        p_phdr = int(first_phdr + (i*phentsize))
        p_phdr = gef.memory.poi(PhdrType, p_phdr)
        yield p_phdr

@gef.memoize.reset_on_stop
def map(pointer, objfile=''):
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
    ei_class, ehdr         = get_ehdr(pointer)

    # For each Program Header which would load data into our
    # address space, create a representation of each individual
    # page and its permissions.
    #
    # Entries are processed in-order so that later entries
    # which change page permissions (e.g. PT_GNU_RELRO) will
    # override their small subset of address space.
    pages = []
    for phdr in iter_phdrs(ehdr):
        memsz   = int(phdr['p_memsz'])

        if not memsz:
            continue

        vaddr   = int(phdr['p_vaddr'])
        offset  = int(phdr['p_offset'])
        flags   = int(phdr['p_flags'])
        ptype   = int(phdr['p_type'])

        memsz += gef.memory.page_offset(vaddr)
        memsz  = gef.memory.page_size_align(memsz)
        vaddr  = gef.memory.page_align(vaddr)
        offset = gef.memory.page_align(offset)

        # For each page described by this program header
        for page_addr in range(vaddr, vaddr+memsz, gef.memory.PAGE_SIZE):
            if page_addr in pages:
                page = pages[pages.index(page_addr)]

                # Don't ever remove the execute flag.
                # Sometimes we'll load a read-only area into .text
                # and the loader doesn't actually *remove* the executable flag.
                if page.flags & PF_X: flags |= PF_X
                page.flags = flags
            else:
                page = gef.memory.Page(page_addr, gef.memory.PAGE_SIZE, flags, offset + (page_addr-vaddr))
                pages.append(page)

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if ET_DYN == int(ehdr['e_type']):
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

    for page in pages:
        page.objfile = objfile

    return tuple(sorted(pages))

@gef.events.stop
def update_main_exe():
    addr = int(exe().address)
    map(addr)