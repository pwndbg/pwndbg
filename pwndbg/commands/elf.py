#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import pwndbg.commands
from elftools.elf.elffile import ELFFile

@pwndbg.commands.Command
def elfheader():
    """
    Prints the section mappings contained in the ELF header.
    """
    exe = str(pwndbg.auxv.get()['AT_EXECFN'])
    with open(exe, 'rb') as f:
        elffile = ELFFile(f)
        load_segment = elffile.get_segment(3)
        segment_base = load_segment['p_vaddr']
        for section in elffile.iter_sections():
            start = section['sh_addr']

            # Don't print sections that aren't mapped into memory
            if start == 0:
                continue

            size = section['sh_size']
            print('%#x - %#x %s' % (start, start + size, section.name.decode('ascii')))

@pwndbg.commands.Command
def gotplt():
    """
    Prints any symbols found in the .got.plt section if it exists.
    """
    print_symbols_in_section('.got.plt', '@got.plt')

@pwndbg.commands.Command
def plt():
    """
    Prints any symbols found in the .plt section if it exists.
    """
    print_symbols_in_section('.plt', '@plt')

def get_section_bounds(section_name):
    section_name = section_name.encode('ascii')
    exe = str(pwndbg.auxv.get()['AT_EXECFN'])
    with open(exe, 'rb') as f:
        elffile = ELFFile(f)

        section = elffile.get_section_by_name(section_name)
        start = section['sh_addr']
        size = section['sh_size']
        return (start, start + size)

def print_symbols_in_section(section_name, filter_text=''):
    start, end = get_section_bounds(section_name)
    if start == None:
        print(pwndbg.color.red('Could not find section'))
        return

    symbols = get_symbols_in_region(start, end, filter_text)
    for symbol, addr in symbols:
        print(hex(addr) + ': ' + symbol)

def get_symbols_in_region(start, end, filter_text=''):
    symbols = []
    ptr_size = pwndbg.typeinfo.pvoid.sizeof
    addr = start
    while addr < end:
        name = pwndbg.symbol.get(addr)
        if name != '' and '+' not in name and filter_text in name:
            symbols.append((name, addr))
        addr += ptr_size

    return symbols
