#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Add, load, show, edit, or delete symbols for custom structures.

For the generation of the symbols g++/gcc is being used under the hood.

In case of remote debugging a binary which is not native to your architecture it 
is advised to configure the 'gcc-config-path' config parameter to your own cross-platform
gnu gcc compiled toolchain for your target architecture.

You are advised to configure the 'cymbol-editor' config parameter to the path of your
favorite text editor. Otherwise cymbol exapnds $EDITOR and $VISUAL environement varialbes
to find the path to the default text editor.
"""

import tempfile
import argparse
import subprocess
import os, sys, gdb

import pwndbg
import pwndbg.lib.gcc
import pwndbg.gdblib.arch
import pwndbg.lib.tempfile
import pwndbg.commands
from pwndbg.color import message

gcc_compiler_path = pwndbg.gdblib.config.add_param(
    "gcc-compiler-path", '', "Path to your own gnu gcc/g++ toolchain for generating imported symbols."
)

cymbol_editor = pwndbg.gdblib.config.add_param(
    "cymbol-editor", '', "Path to your editor of your choice for editing custom structures."
)

def OnlyWhenStructureExists(func):
    def wrapper(custom_structure_name):
        pwndbg_cachedir = pwndbg.lib.tempfile.cachedir('custom-symbols')
        pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + '.c'

        if not os.path.exists(pwndbg_custom_structure_path):
            print(
                message.error('No custom structure was found with the given name!')
            )
            return

        return func(custom_structure_name, pwndbg_custom_structure_path)
    return wrapper

def PromptForOverwrite(func):
    def wrapper(custom_structure_name):
        pwndbg_cachedir = pwndbg.lib.tempfile.cachedir('custom-symbols')
        pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + '.c'

        if not os.path.exists(pwndbg_custom_structure_path):
            return func(custom_structure_name)
    
        option = input(
            message.notice('A custom structure was found with the given name, would you like to overwrite it? [y/n] ')
        )

        if option != 'y':
            return
        
        return func(custom_structure_name)
    return wrapper  

def generate_debug_symbols(custom_structure_path, pwndbg_debug_symbols_output_file = None):
    if not pwndbg_debug_symbols_output_file:
        _, pwndbg_debug_symbols_output_file = tempfile.mkstemp(prefix='custom-', suffix='.dbg')
    
    # -fno-eliminate-unused-debug-types is a handy gcc flag that lets us extract debug symbols from non-used defined structures.
    gcc_extra_flags = [custom_structure_path, '-c', '-g', '-fno-eliminate-unused-debug-types', '-o', pwndbg_debug_symbols_output_file]
    gcc_flags = None

    if gcc_compiler_path != '':
        if pwndbg.gdblib.arch.ptrsize == 8:
            gcc_flags = [gcc_compiler_path, '-m64']
        elif pwndbg.gdblib.arch.ptrsize == 4:
            gcc_flags = [gcc_compiler_path, '-m32']
    else:
        # Should we check for exceptions here?
        gcc_flags = pwndbg.lib.gcc.which(pwndbg.gdblib.arch)

    gcc_cmd = gcc_flags + gcc_extra_flags

    try:
        subprocess.run(gcc_cmd, capture_output=False, check=True)
    except subprocess.CalledProcessError as exepction:
        print(
            message.error(exepction)
        )
        print(
            message.error('Parsing failed, try to fix any syntax errors first.')
        )
        return None
    except Exception as exepction:
        print(
            message.error(exepction)
        )
        print(
            message.error('An error occured while generating the debug symbols.')
        )
        return None
    
    return pwndbg_debug_symbols_output_file

@PromptForOverwrite
def add_custom_structure(custom_structure_name):
    print(
        message.notice('Enter your custom structure in a C header style, press Ctrl+D to save:\n')
    )

    custom_structures_source = sys.stdin.read().strip()
    if custom_structures_source == '':
        print(
            message.notice('An empty structure is entered, skipping ...')
        )
        return

    pwndbg_cachedir = pwndbg.lib.tempfile.cachedir('custom-symbols')
    pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + '.c'

    with open(pwndbg_custom_structure_path, "w") as f:
        f.write(custom_structures_source)
    
    pwndbg_debug_symbols_output_file = generate_debug_symbols(pwndbg_custom_structure_path)
    if not pwndbg_debug_symbols_output_file:
        return
    
    gdb.execute(f'add-symbol-file {pwndbg_debug_symbols_output_file}', to_string=True)
    print(
        message.success('Symbols are added!')
    )

@OnlyWhenStructureExists
def edit_custom_structure(custom_structure_name, custom_structure_path):

    # Lookup an editor to use for editing the custom structure.
    editor_preference = os.getenv('EDITOR')
    if not editor_preference:
        editor_preference = os.getenv('VISUAL')
    if not editor_preference:
        editor_preference = 'vi'
    
    if cymbol_editor != '':
        editor_preference = cymbol_editor
    
    try:
        subprocess.run([editor_preference, custom_structure_path], capture_output=False, check=True)
    except Exception as exepction:
        print(
            message.error('An error occured during opening the source file.')
        )
        print(
            message.error(f'Path to the custom structure: {custom_structure_path}')
        )
        print(
            message.error('Please try to manually edit the structure.')
        )
        print(
            message.error('\nTry to set a path to an editor with:\n\tset "cymbol-editor" /usr/bin/nano')
        )
        return
    
    input(
        message.notice('Press enter to continue.')
    )

    load_custom_structure(custom_structure_name)

@OnlyWhenStructureExists
def remove_custom_structure(custom_structure_name, custom_structure_path):
    os.remove(custom_structure_path)
    print(
        message.success('Symbols are removed!')
    )
    print(
        message.notice('If the symbols are already loaded, please restart pwndbg to unload them from memory.')
    )

@OnlyWhenStructureExists
def load_custom_structure(custom_structure_name, custom_structure_path):
    pwndbg_debug_symbols_output_file = generate_debug_symbols(custom_structure_path)
    if not pwndbg_debug_symbols_output_file:
        return
    gdb.execute(f'add-symbol-file {pwndbg_debug_symbols_output_file}', to_string=True)
    print(
        message.success('Symbols are loaded!')
    )

@OnlyWhenStructureExists
def show_custom_structure(custom_structure_name, custom_structure_path):
    print()
    with open(custom_structure_path, 'r') as f:
        print(f.read())
    print()

parser = argparse.ArgumentParser(description="Add, show, load, edit, or delete custom structures in plain C")
parser.add_argument(
    "-a",
    "--add",
    metavar="name",
    help="Add a new custom structure",
    default=None,
    type=str,
)
parser.add_argument(
    "-r",
    "--remove",
    metavar="name",
    help="Remove an existing custom structure",
    default=None,
    type=str,
)
parser.add_argument(
    "-e",
    "--edit",
    metavar="name",
    help="Edit an existing custom structure",
    default=None,
    type=str,
)
parser.add_argument(
    "-l",
    "--load",
    metavar="name",
    help="Load an existing custom structure",
    default=None,
    type=str,
)
parser.add_argument(
    "-s",
    "--show",
    metavar="name",
    help="Show the source code of an existing custom structure",
    default=None,
    type=str,
)

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyAmd64
@pwndbg.commands.OnlyWhenRunning
def cymbol(add, remove, edit, load, show):
    if add:
        add_custom_structure(add)
        return
    
    if remove:
        remove_custom_structure(remove)
        return
    
    if edit:
        edit_custom_structure(edit)
        return
    
    if load:
        load_custom_structure(load)
        return
    
    if show:
        show_custom_structure(show)
        return
    
    parser.print_help()