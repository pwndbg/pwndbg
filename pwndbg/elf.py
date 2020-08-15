#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This file declares types and methods useful for enumerating
all of the address spaces and permissions of an ELF file in memory.

This is necessary for when access to /proc is restricted, or when
working on a BSD system which simply does not have /proc.
"""

import ctypes
import sys
from collections import namedtuple

import gdb
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from six.moves import reload_module

import pwndbg.abi
import pwndbg.arch
import pwndbg.auxv
import pwndbg.elftypes
import pwndbg.events
import pwndbg.info
import pwndbg.memoize
import pwndbg.memory
import pwndbg.proc
import pwndbg.stack

# ELF constants
PF_X, PF_W, PF_R = 1,2,4
ET_EXEC, ET_DYN  = 2,3


module = sys.modules[__name__]


class ELFInfo(namedtuple('ELFInfo', 'header sections segments')):
    """
    ELF metadata and structures.
    """
    @property
    def is_pic(self):
        return self.header['e_type'] == 'ET_DYN'

    @property
    def is_pie(self):
        return self.is_pic


@pwndbg.events.start
@pwndbg.events.new_objfile
def update():
    reload_module(pwndbg.elftypes)

    if pwndbg.arch.ptrsize == 4:
        Ehdr = pwndbg.elftypes.Elf32_Ehdr
        Phdr = pwndbg.elftypes.Elf32_Phdr
    else:
        Ehdr = pwndbg.elftypes.Elf64_Ehdr
        Phdr = pwndbg.elftypes.Elf64_Phdr

    module.__dict__.update(locals())

update()


def read(typ, address, blob=None):
    size = ctypes.sizeof(typ)

    if not blob:
        data = pwndbg.memory.read(address, size)
    else:
        data = blob[address:address+size]

    obj = typ.from_buffer_copy(data)
    obj.address = address
    obj.type = typ
    return obj


@pwndbg.memoize.reset_on_objfile
def get_elf_info(filepath):
    """
    Parse and return ELFInfo.

    Adds various calculated properties to the ELF header, segments and sections.
    Such added properties are those with prefix 'x_' in the returned dicts.
    """
    local_path = pwndbg.file.get_file(filepath)
    with open(local_path, 'rb') as f:
        elffile = ELFFile(f)
        header = dict(elffile.header)
        segments = []
        for seg in elffile.iter_segments():
            s = dict(seg.header)
            s['x_perms'] = [
                mnemonic for mask, mnemonic in [(PF_R, 'read'), (PF_W, 'write'), (PF_X, 'execute')]
                if s['p_flags'] & mask != 0
            ]
            # end of memory backing
            s['x_vaddr_mem_end'] = s['p_vaddr'] + s['p_memsz']
            # end of file backing
            s['x_vaddr_file_end'] = s['p_vaddr'] + s['p_filesz']
            segments.append(s)
        sections = []
        for sec in elffile.iter_sections():
            s = dict(sec.header)
            s['x_name'] = sec.name
            s['x_addr_mem_end'] = s['x_addr_file_end'] = s['sh_addr'] + s['sh_size']
            sections.append(s)
        return ELFInfo(header, sections, segments)


@pwndbg.memoize.reset_on_objfile
def get_elf_info_rebased(filepath, vaddr):
    """
    Parse and return ELFInfo with all virtual addresses rebased to vaddr
    """
    raw_info = get_elf_info(filepath)
    # silently ignores "wrong" vaddr supplied for non-PIE ELF
    load = vaddr if raw_info.is_pic else 0
    headers = dict(raw_info.header)
    headers['e_entry'] += load

    segments = []
    for seg in raw_info.segments:
        s = dict(seg)
        for vaddr_attr in ['p_vaddr', 'x_vaddr_mem_end', 'x_vaddr_file_end']:
            s[vaddr_attr] += load
        segments.append(s)

    sections = []
    for sec in raw_info.sections:
        s = dict(sec)
        for vaddr_attr in ['sh_addr', 'x_addr_mem_end', 'x_addr_file_end']:
            s[vaddr_attr] += load
        sections.append(s)

    return ELFInfo(headers, sections, segments)


def get_containing_segments(elf_filepath, elf_loadaddr, vaddr):
    elf = get_elf_info_rebased(elf_filepath, elf_loadaddr)
    segments = []
    for seg in elf.segments:
        # disregard segments which were unable to be named by pyelftools (see #777)
        # and non-LOAD segments that are not file-backed (typically STACK)
        if isinstance(seg['p_type'], int) or ('LOAD' not in seg['p_type'] and seg['p_filesz'] == 0):
            continue
        # disregard segments not containing vaddr
        if vaddr < seg['p_vaddr'] or vaddr >= seg['x_vaddr_mem_end']:
            continue
        segments.append(dict(seg))
    return segments


def get_containing_sections(elf_filepath, elf_loadaddr, vaddr):
    elf = get_elf_info_rebased(elf_filepath, elf_loadaddr)
    sections = []
    for sec in elf.sections:
        # disregard sections not occupying memory
        if sec['sh_flags'] & SH_FLAGS.SHF_ALLOC == 0:
            continue
        # disregard sections that do not contain vaddr
        if vaddr < sec['sh_addr'] or vaddr >= sec['x_addr_mem_end']:
            continue
        sections.append(dict(sec))
    return sections


@pwndbg.proc.OnlyWhenRunning
@pwndbg.memoize.reset_on_start
def exe():
    """
    Return a loaded ELF header object pointing to the Ehdr of the
    main executable.
    """
    e = entry()
    if e:
        return load(e)


@pwndbg.proc.OnlyWhenRunning
@pwndbg.memoize.reset_on_start
def entry():
    """
    Return the address of the entry point for the main executable.
    """
    entry = pwndbg.auxv.get().AT_ENTRY
    if entry:
        return entry

    # Looking for this line:
    # Entry point: 0x400090
    for line in pwndbg.info.files().splitlines():
        if "Entry point" in line:
            entry_point = int(line.split()[-1], 16)

            # PIE entry points are sometimes reported as an
            # offset from the module base.
            if entry_point < 0x10000:
                break

            return entry_point

    # Try common names
    for name in ['_start', 'start', '__start', 'main']:
        try:
            return pwndbg.symbol.address(name)
        except gdb.error:
            pass

    # Can't find it, give up.
    return 0


def load(pointer):
    return get_ehdr(pointer)[1]

ehdr_type_loaded = 0


@pwndbg.memoize.reset_on_start
def reset_ehdr_type_loaded():
    global ehdr_type_loaded
    ehdr_type_loaded = 0


@pwndbg.abi.LinuxOnly()
def find_elf_magic(pointer, max_pages=1024, search_down=False, ret_addr_anyway=False):
    """Search the nearest page which contains the ELF headers
    by comparing the ELF magic with first 4 bytes.

    Parameter:
        search_down: change the search direction
        to search over the lower address.
        That is, decreasing the page pointer instead of increasing.
            (default: False)
    Returns:
        An integer address of ELF page base
        None if not found within the page limit
    """
    addr = pwndbg.memory.page_align(pointer)
    step = pwndbg.memory.PAGE_SIZE
    if search_down:
        step = -step

    max_addr = pwndbg.arch.ptrmask

    for i in range(max_pages):
        # Make sure address within valid range or gdb will raise Overflow exception
        if addr < 0 or addr > max_addr:
            return None

        try:
            data = pwndbg.memory.read(addr, 4)
        except gdb.MemoryError:
            return addr if ret_addr_anyway else None

        # Return the address if found ELF header
        if data == b'\x7FELF':
            return addr

        addr += step

    return addr if ret_addr_anyway else None


def get_ehdr(pointer):
    """Returns an ehdr object for the ELF pointer points into.
    """
    # Align down to a page boundary, and scan until we find
    # the ELF header.
    base = pwndbg.memory.page_align(pointer)

    # For non linux ABI, the ELF header may not be found in memory.
    # This will hang the gdb when using the remote gdbserver to scan 1024 pages
    base = find_elf_magic(pointer, search_down=True)
    if base is None:
        if pwndbg.abi.linux:
            print("ERROR: Could not find ELF base!")
        return None, None

    # Determine whether it's 32- or 64-bit
    ei_class = pwndbg.memory.byte(base+4)

    # Find out where the section headers start
    Elfhdr   = read(Ehdr, base)
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

    phnum     = Elfhdr.e_phnum
    phoff     = Elfhdr.e_phoff
    phentsize = Elfhdr.e_phentsize

    x = (phnum, phentsize, read(Phdr, Elfhdr.address + phoff))
    return x


def iter_phdrs(ehdr):
    if not ehdr:
        return

    phnum, phentsize, phdr = get_phdrs(ehdr.address)

    if not phdr:
        return

    first_phdr = phdr.address
    PhdrType   = phdr.type

    for i in range(0, phnum):
        p_phdr = int(first_phdr + (i*phentsize))
        p_phdr = read(PhdrType, p_phdr)
        yield p_phdr


def map(pointer, objfile=''):
    """
    Given a pointer into an ELF module, return a list of all loaded
    sections in the ELF.

    Returns:
        A sorted list of pwndbg.memory.Page objects

    Example:

        >>> pwndbg.elf.load(pwndbg.regs.pc)
        [Page('400000-4ef000 r-xp 0'),
         Page('6ef000-6f0000 r--p ef000'),
         Page('6f0000-6ff000 rw-p f0000')]
        >>> pwndbg.elf.load(0x7ffff77a2000)
        [Page('7ffff75e7000-7ffff77a2000 r-xp 0x1bb000 0'),
         Page('7ffff77a2000-7ffff79a2000 ---p 0x200000 1bb000'),
         Page('7ffff79a2000-7ffff79a6000 r--p 0x4000 1bb000'),
         Page('7ffff79a6000-7ffff79ad000 rw-p 0x7000 1bf000')]
    """
    ei_class, ehdr         = get_ehdr(pointer)
    return map_inner(ei_class, ehdr, objfile)


def map_inner(ei_class, ehdr, objfile):
    if not ehdr:
        return []

    base = int(ehdr.address)

    # For each Program Header which would load data into our
    # address space, create a representation of each individual
    # page and its permissions.
    #
    # Entries are processed in-order so that later entries
    # which change page permissions (e.g. PT_GNU_RELRO) will
    # override their small subset of address space.
    pages = []
    for phdr in iter_phdrs(ehdr):
        memsz   = int(phdr.p_memsz)

        if not memsz:
            continue

        vaddr   = int(phdr.p_vaddr)
        offset  = int(phdr.p_offset)
        flags   = int(phdr.p_flags)
        ptype   = int(phdr.p_type)

        memsz += pwndbg.memory.page_offset(vaddr)
        memsz  = pwndbg.memory.page_size_align(memsz)
        vaddr  = pwndbg.memory.page_align(vaddr)
        offset = pwndbg.memory.page_align(offset)

        # For each page described by this program header
        for page_addr in range(vaddr, vaddr+memsz, pwndbg.memory.PAGE_SIZE):
            if page_addr in pages:
                page = pages[pages.index(page_addr)]

                # Don't ever remove the execute flag.
                # Sometimes we'll load a read-only area into .text
                # and the loader doesn't actually *remove* the executable flag.
                if page.flags & PF_X: flags |= PF_X
                page.flags = flags
            else:
                page = pwndbg.memory.Page(page_addr, pwndbg.memory.PAGE_SIZE, flags, offset + (page_addr-vaddr))
                pages.append(page)

    # Adjust against the base address that we discovered
    # for binaries that are relocatable / type DYN.
    if ET_DYN == int(ehdr.e_type):
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
            gaps.append(pwndbg.memory.Page(a_end, b_begin-a_end, 0, b.offset))

    pages.extend(gaps)

    for page in pages:
        page.objfile = objfile

    return tuple(sorted(pages))
