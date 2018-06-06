#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import subprocess

import gdb

import pwndbg.arch
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.config
import pwndbg.memory
import pwndbg.regs
import pwndbg.stack
import pwndbg.vmmap
import pwndbg.wrappers

parser = argparse.ArgumentParser(description='Shows offsets of the specified address to useful other locations')
parser.add_argument('address', nargs='?', default='$pc',
                    help='Address to inspect')

def print_line(name, addr, first, second, op, width = 20):

    print("{} {} = {} {} {:#x}".format(name.rjust(width), M.get(addr),
        M.get(first) if type(first) is not str else first.ljust(len(hex(addr))),
        op, second,))

def xinfo_stack(page, addr):
    # If it's a stack address, print offsets to top and bottom of stack, as
    # well as offsets to current stack and base pointer (if used by debugee)

    sp = pwndbg.regs.sp
    frame = pwndbg.regs[pwndbg.regs.frame]
    frame_mapping = pwndbg.vmmap.find(frame)

    print_line("Stack Top", addr, page.vaddr, addr - page.vaddr, "+")
    print_line("Stack End", addr, page.end, page.end - addr, "-")
    print_line("Stack Pointer", addr, sp, addr - sp, "+")

    if frame_mapping and page.vaddr == frame_mapping.vaddr:
        print_line("Frame Pointer", addr, frame, frame - addr, "-")

    canary_value = pwndbg.commands.canary.canary_value()[0]

    if canary_value is not None:
        all_canaries = list(
            pwndbg.search.search(pwndbg.arch.pack(canary_value), mappings=pwndbg.stack.stacks.values())
        )
        follow_canaries = sorted(filter(lambda a: a > addr, all_canaries))
        if follow_canaries is not None and len(follow_canaries) > 0:
            nxt = follow_canaries[0]
            print_line("Next Stack Canary", addr, nxt, nxt - addr, "-")

def xinfo_mmap_file(page, addr):
    # If it's an address pointing into a memory mapped file, print offsets
    # to beginning of file in memory and on disk

    file_name = page.objfile
    objpages = filter(lambda p: p.objfile == file_name, pwndbg.vmmap.get())
    first = sorted(objpages, key = lambda p: p.vaddr)[0]
    rva = addr - first.vaddr

    print_line("File (Memory)", addr, first.vaddr, rva, "+")

    file_offset = None
    for segment in pwndbg.elf.get_containing_segments(file_name, addr, first.vaddr):
        if segment['p_type'] == 'PT_LOAD' and addr < segment['x_file_backing_end']:
            file_offset = segment['p_offset'] + (addr - segment['x_real_vaddr_start'])
            print_line("File (Disk)", addr, file_name, file_offset, "+")
            break

    if file_offset is None:
        print('{} {} = [not file-backed]'.format('File (Disk)'.rjust(20), M.get(addr)))

    else:
        print('\n Containing ELF sections:')
        for sec in pwndbg.elf.get_containing_sections(file_name, addr, first.vaddr):
            print('{} {} = {} + {:#x}'.format(
                sec['x_name'].rjust(20),
                M.get(addr),
                M.get(sec['x_real_vaddr_start']),
                addr - sec['sh_addr']
            ))



def xinfo_default(page, addr):
    # Just print the distance to the beginning of the mapping

    print_line("Mapped Area", addr, page.vaddr, addr - page.vaddr, "+")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def xinfo(address=None):
    addr = int(address)
    addr &= pwndbg.arch.ptrmask

    page = pwndbg.vmmap.find(addr)

    if page is None:
        print("\n  Virtual address {:#x} is not mapped.".format(addr))
        return

    print("Extended information for virtual address {}:".format(M.get(addr)))

    print("\n  Containing mapping:")
    print(M.get(address, text=str(page)))

    print("\n  Offset information:")

    if page.is_stack:
        xinfo_stack(page, addr)
    else:
        xinfo_default(page, addr)

    if page.is_memory_mapped_file:
        xinfo_mmap_file(page, addr)
