#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to print the virtual memory map a la /proc/self/maps.
"""
import argparse

import gdb
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.elf
import pwndbg.vmmap

integer_types = (int, gdb.Value)


def pages_filter(gdbval_or_str):
    # returns a module filter
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    elif isinstance(gdbval_or_str, integer_types):
        addr = gdbval_or_str
        return lambda page: addr in page

    else:
        raise argparse.ArgumentTypeError('Unknown vmmap argument type.')


parser = argparse.ArgumentParser()
parser.description = '''Print virtual memory map pages. Results can be filtered by providing address/module name.

Memory pages on QEMU targets may be inaccurate. This is because:
- for QEMU kernel on X86/X64 we fetch memory pages via `monitor info mem` and it doesn't inform if memory page is executable
- for QEMU user emulation we detected memory pages through AUXV (sometimes by finding AUXV on the stack first)
- for others, we create mempages by exploring current register values (this is least correct)

Memory pages can also be added manually, see vmmap_add, vmmap_clear and vmmap_load commands.'''
parser.formatter_class=argparse.RawDescriptionHelpFormatter
parser.add_argument('gdbval_or_str', type=pwndbg.commands.sloppy_gdb_parse, nargs='?', default=None,
                    help='Address or module name.')


@pwndbg.commands.ArgparsedCommand(parser, aliases=['lm', 'address', 'vprot'])
@pwndbg.commands.OnlyWhenRunning
def vmmap(gdbval_or_str=None):
    pages = pwndbg.vmmap.get()

    if gdbval_or_str:
        pages = list(filter(pages_filter(gdbval_or_str), pages))

    if not pages:
        print('There are no mappings for specified address or module.')
        return

    print(M.legend())

    if len(pages) == 1 and isinstance(gdbval_or_str, integer_types):
        page = pages[0]
        print(M.get(page.vaddr, text=str(page) + ' +0x%x' % (int(gdbval_or_str) - page.vaddr)))
    else:
        for page in pages:
            print(M.get(page.vaddr, text=str(page)))

    if pwndbg.qemu.is_qemu():
        print("\n[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]")


parser = argparse.ArgumentParser()
parser.description = 'Add Print virtual memory map page.'
parser.add_argument('start', help='Starting virtual address')
parser.add_argument('size', help='Size of the address space, in bytes')
parser.add_argument('flags', nargs='?', type=str, default='', help='Flags set by the ELF file, see PF_X, PF_R, PF_W')
parser.add_argument('offset', nargs='?', default=0, help='Offset into the original ELF file that the data is loaded from')

@pwndbg.commands.ArgparsedCommand(parser)
def vmmap_add(start, size, flags, offset):
    page_flags = {
        'r': pwndbg.elf.PF_R,
        'w': pwndbg.elf.PF_W,
        'x': pwndbg.elf.PF_X,
    }
    perm = 0
    for flag in flags:
        flag_val = page_flags.get(flag, None)
        if flag_val is None:
            print('Invalid page flag "%s"', flag)
            return
        perm |= flag_val

    page = pwndbg.memory.Page(start, size, perm, offset)
    pwndbg.vmmap.add_custom_page(page)

    print('%r added' % page)


@pwndbg.commands.ArgparsedCommand("Clear the vmmap cache.") #TODO is this accurate?
def vmmap_clear():
    pwndbg.vmmap.clear_custom_page()


parser = argparse.ArgumentParser()
parser.description = 'Load virtual memory map pages from ELF file.'
parser.add_argument('filename', nargs='?', type=str, help='ELF filename, by default uses current loaded filename.')

@pwndbg.commands.ArgparsedCommand(parser)
def vmmap_load(filename):
    if filename is None:
        filename = pwndbg.proc.exe

    print('Load "%s" ...' % filename)

    # TODO: Add an argument to let use to choose loading the page information from sections or segments

    # Use section information to recover the segment information.
    # The entry point of bare metal enviroment is often at the first segment.
    # For example, assume the entry point is at 0x8000.
    # In most of case, link will create a segment and starts from 0x0.
    # This cause all values less than 0x8000 be considered as a valid pointer.
    pages = []
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            vaddr = section['sh_addr']
            memsz = section['sh_size']
            sh_flags = section['sh_flags']
            offset = section['sh_offset']

            # Don't add the sections that aren't mapped into memory
            if not sh_flags & SH_FLAGS.SHF_ALLOC:
                continue

            # Guess the segment flags from section flags
            flags = pwndbg.elf.PF_R
            if sh_flags & SH_FLAGS.SHF_WRITE:
                flags |= pwndbg.elf.PF_W
            if sh_flags & SH_FLAGS.SHF_EXECINSTR:
                flags |= pwndbg.elf.PF_X

            page = pwndbg.memory.Page(vaddr, memsz, flags, offset, filename)
            pages.append(page)

    for page in pages:
        pwndbg.vmmap.add_custom_page(page)
        print('%r added' % page)
