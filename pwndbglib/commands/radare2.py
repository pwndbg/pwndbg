#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import subprocess

import pwndbglib.color.message as message
import pwndbglib.commands
import pwndbglib.radare2

parser = argparse.ArgumentParser(description='Launches radare2',
                                 epilog="Example: r2 -- -S -AA")
parser.add_argument('--no-seek', action='store_true',
                    help='Do not seek to current pc')
parser.add_argument('--no-rebase', action='store_true',
                    help='Do not set the base address for PIE according to the current mapping')
parser.add_argument('arguments', nargs='*', type=str,
                    help='Arguments to pass to radare')


@pwndbglib.commands.ArgparsedCommand(parser, aliases=['radare2'])
@pwndbglib.commands.OnlyWithFile
def r2(arguments, no_seek=False, no_rebase=False):
    filename = pwndbglib.file.get_file(pwndbglib.proc.exe)

    # Build up the command line to run
    cmd = ['radare2']
    flags = ['-e', 'io.cache=true']
    if pwndbglib.proc.alive:
        addr = pwndbglib.regs.pc
        if pwndbglib.elf.get_elf_info(filename).is_pie:
            if no_rebase:
                addr -= pwndbglib.elf.exe().address
            else:
                flags.extend(['-B', hex(pwndbglib.elf.exe().address)])
        if not no_seek:
            cmd.extend(['-s', hex(addr)])
    cmd.extend(flags)
    cmd += arguments
    cmd.extend([filename])

    try:
        subprocess.call(cmd)
    except Exception:
        print("Could not run radare2. Please ensure it's installed and in $PATH.")


parser = argparse.ArgumentParser(description='Execute stateful radare2 commands through r2pipe',
                                 epilog="Example: r2pipe pdf sym.main")
parser.add_argument('arguments', nargs='+', type=str,
                    help='Arguments to pass to r2pipe')


@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWithFile
def r2pipe(arguments):
    try:
        r2 = pwndbglib.radare2.r2pipe()
        print(r2.cmd(' '.join(arguments)))
    except ImportError:
        print(message.error("Could not import r2pipe python library"))
    except Exception as e:
        print(message.error(e))
