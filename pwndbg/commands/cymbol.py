#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Add, load, show, edit, or delete symbols for custom structures.

For the generation of the symbols g++/gcc is being used under the hood.

In case of remote debugging a binary which is not native to your architecture it
is advised to configure the 'gcc-config-path' config parameter to your own cross-platform
gnu gcc compiled toolchain for your target architecture.

You are advised to configure the 'cymbol-editor' config parameter to the path of your
favorite text editor. Otherwise cymbol exapnds $EDITOR and $VISUAL environment variables
to find the path to the default text editor.
"""

import argparse
import functools
import os
import subprocess
import sys
import tempfile

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.lib.gcc
import pwndbg.lib.tempfile
from pwndbg.color import message

gcc_compiler_path = pwndbg.gdblib.config.add_param(
    "gcc-compiler-path",
    "",
    "Path to the gcc/g++ toolchain for generating imported symbols",
)

cymbol_editor = pwndbg.gdblib.config.add_param(
    "cymbol-editor", "", "Path to the editor for editing custom structures"
)

# Remeber loaded symbols. This would be useful for 'remove-symbol-file'.
loaded_symbols = {}

# Where generated symbol source files are saved.
pwndbg_cachedir = pwndbg.lib.tempfile.cachedir("custom-symbols")


def unload_loaded_symbol(custom_structure_name):
    custom_structure_symbols_file = loaded_symbols.get(custom_structure_name)
    if custom_structure_symbols_file is not None:
        gdb.execute(f"remove-symbol-file {custom_structure_symbols_file}")
        loaded_symbols.pop(custom_structure_name)


def OnlyWhenStructFileExists(func):
    @functools.wraps(func)
    def wrapper(custom_structure_name):
        pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + ".c"
        if not os.path.exists(pwndbg_custom_structure_path):
            print(message.error("No custom structure was found with the given name!"))
            return
        return func(custom_structure_name, pwndbg_custom_structure_path)

    return wrapper


def generate_debug_symbols(custom_structure_path, pwndbg_debug_symbols_output_file=None):
    if not pwndbg_debug_symbols_output_file:
        _, pwndbg_debug_symbols_output_file = tempfile.mkstemp(prefix="custom-", suffix=".dbg")

    # -fno-eliminate-unused-debug-types is a handy gcc flag that lets us extract debug symbols from non-used defined structures.
    gcc_extra_flags = [
        custom_structure_path,
        "-c",
        "-g",
        "-fno-eliminate-unused-debug-types",
        "-o",
        pwndbg_debug_symbols_output_file,
    ]

    # TODO: implement remote debugging support.
    gcc_flags = pwndbg.lib.gcc.which(pwndbg.gdblib.arch)
    if gcc_compiler_path != "":
        gcc_flags[0] = gcc_compiler_path

    gcc_cmd = gcc_flags + gcc_extra_flags

    try:
        subprocess.run(gcc_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    except subprocess.CalledProcessError as exception:
        print(message.error(exception))
        print(
            message.error(
                "Failed to compile the .c file with custom structures. Please fix any compilation errors there may be."
            )
        )
        return None
    except Exception as exception:
        print(message.error(exception))
        print(message.error("An error occured while generating the debug symbols."))
        return None

    return pwndbg_debug_symbols_output_file


def add_custom_structure(custom_structure_name):
    pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + ".c"

    if os.path.exists(pwndbg_custom_structure_path):
        option = input(
            message.notice(
                "A custom structure was found with the given name, would you like to overwrite it? [y/n] "
            )
        )
        if option != "y":
            return

    print(
        message.notice("Enter your custom structure in a C header style, press Ctrl+D to save:\n")
    )

    custom_structures_source = sys.stdin.read().strip()
    if custom_structures_source == "":
        print(message.notice("An empty structure is entered, skipping ..."))
        return

    with open(pwndbg_custom_structure_path, "w") as f:
        f.write(custom_structures_source)

    # Avoid checking for file existance. Call the decorator wrapper directly.
    load_custom_structure.__wrapped__(custom_structure_name, pwndbg_custom_structure_path)


@OnlyWhenStructFileExists
def edit_custom_structure(custom_structure_name, custom_structure_path):

    # Lookup an editor to use for editing the custom structure.
    editor_preference = os.getenv("EDITOR")
    if not editor_preference:
        editor_preference = os.getenv("VISUAL")
    if not editor_preference:
        editor_preference = "vi"

    if cymbol_editor != "":
        editor_preference = cymbol_editor

    try:
        subprocess.run(
            [editor_preference, custom_structure_path],
            check=True,
        )
    except Exception as exception:
        print(message.error("An error occured during opening the source file."))
        print(message.error(f"Path to the custom structure: {custom_structure_path}"))
        print(message.error("Please try to manually edit the structure."))
        print(
            message.error(
                '\nTry to set a path to an editor with:\n\tset "cymbol-editor" /usr/bin/nano'
            )
        )
        return

    input(message.notice("Press enter when finished editing."))

    load_custom_structure(custom_structure_name)


@OnlyWhenStructFileExists
def remove_custom_structure(custom_structure_name, custom_structure_path):
    unload_loaded_symbol(custom_structure_name)
    os.remove(custom_structure_path)
    print(message.success("Symbols are removed!"))


@OnlyWhenStructFileExists
def load_custom_structure(custom_structure_name, custom_structure_path):
    unload_loaded_symbol(custom_structure_name)
    pwndbg_debug_symbols_output_file = generate_debug_symbols(custom_structure_path)
    if not pwndbg_debug_symbols_output_file:
        return  # generate_debug_symbols prints on failures
    # Old GDB versions (e.g. 8.2) requires addr argument in add-symbol-file
    # we set that address to which to load the symbols to 0 since it doesn't matter here
    # (because we are only loading types information)
    gdb.execute(f"add-symbol-file {pwndbg_debug_symbols_output_file} 0", to_string=True)
    loaded_symbols[custom_structure_name] = pwndbg_debug_symbols_output_file
    print(message.success("Symbols are loaded!"))


@OnlyWhenStructFileExists
def show_custom_structure(custom_structure_name, custom_structure_path):
    # Call wrapper .func() to avoid memoization.
    highlighted_source = pwndbg.pwndbg.commands.context.get_highlight_source.func(
        custom_structure_path
    )
    print("\n".join(highlighted_source))


parser = argparse.ArgumentParser(
    description="Add, show, load, edit, or delete custom structures in plain C"
)
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
    elif remove:
        remove_custom_structure(remove)
    elif edit:
        edit_custom_structure(edit)
    elif load:
        load_custom_structure(load)
    elif show:
        show_custom_structure(show)
    else:
        parser.print_help()
