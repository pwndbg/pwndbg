#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import subprocess

import pwndbg.commands

parser = argparse.ArgumentParser(description='Launches radare2',
                                 epilog="Example: r2 -- -S -AA")
parser.add_argument('--no-seek', action='store_true',
                    help='Do not seek to current pc')
parser.add_argument('--no-rebase', action='store_true',
                    help='Do not set the base address for PIE according to the current mapping')
parser.add_argument('arguments', nargs='*', type=str,
                    help='Arguments to pass to radare')


@pwndbg.commands.ArgparsedCommand(parser, aliases=['radare2'])
@pwndbg.commands.OnlyWithFile
def r2(arguments, no_seek=False, no_rebase=False):
    filename = pwndbg.file.get_file(pwndbg.proc.exe)

    # Build up the command line to run
    cmd = ['radare2']
    flags = []
    if pwndbg.proc.alive:
        addr = pwndbg.regs.pc
        if pwndbg.elf.get_elf_info(filename).is_pie:
            if no_rebase:
                addr -= pwndbg.elf.exe().address
            else:
                flags.extend(['-B', hex(pwndbg.elf.exe().address)])
        if not no_seek:
            cmd.extend(['-s', hex(addr)])
    cmd.extend(flags)
    cmd += arguments
    cmd.extend([filename])

    try:
        subprocess.call(cmd)
    except Exception:
        print("Could not run radare2. Please ensure it's installed and in $PATH.")
