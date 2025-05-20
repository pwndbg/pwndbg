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

from __future__ import annotations

import argparse
import functools
import os
import subprocess
import sys
import tempfile
from typing import Dict
from typing import TypeVar

import gdb
from typing_extensions import ParamSpec
from typing_extensions import Protocol

import pwndbg
import pwndbg.aglib.arch
import pwndbg.commands
import pwndbg.lib.config
import pwndbg.lib.gcc
import pwndbg.lib.tempfile
from pwndbg.color import message
from pwndbg.commands import CommandCategory

P = ParamSpec("P")
T = TypeVar("T")

gcc_compiler_path = pwndbg.config.add_param(
    "gcc-compiler-path",
    "",
    "path to the gcc/g++ toolchain for generating imported symbols",
    param_class=pwndbg.lib.config.PARAM_OPTIONAL_FILENAME,
)

cymbol_editor = pwndbg.config.add_param(
    "cymbol-editor",
    "",
    "path to the editor for editing custom structures",
    param_class=pwndbg.lib.config.PARAM_OPTIONAL_FILENAME,
)

# Remeber loaded symbols. This would be useful for 'remove-symbol-file'.
loaded_symbols: Dict[str, str] = {}

# Where generated symbol source files are saved.
pwndbg_cachedir = pwndbg.lib.tempfile.cachedir("custom-symbols")


def unload_loaded_symbol(custom_structure_name: str) -> None:
    custom_structure_symbols_file = loaded_symbols.get(custom_structure_name)
    if custom_structure_symbols_file is not None:
        gdb.execute(f"remove-symbol-file {custom_structure_symbols_file}")
        loaded_symbols.pop(custom_structure_name)


class _OnlyWhenStructFileExists(Protocol):
    def __call__(self, custom_structure_name: str, custom_structure_path: str = "") -> T | None: ...


def OnlyWhenStructFileExists(func: _OnlyWhenStructFileExists) -> _OnlyWhenStructFileExists:
    @functools.wraps(func)
    def wrapper(custom_structure_name: str, custom_structure_path: str = "") -> T | None:
        pwndbg_custom_structure_path = (
            custom_structure_path or os.path.join(pwndbg_cachedir, custom_structure_name) + ".c"
        )
        if not os.path.exists(pwndbg_custom_structure_path):
            print(message.error("No custom structure was found with the given name!"))
            return None
        return func(custom_structure_name, pwndbg_custom_structure_path)

    return wrapper


def generate_debug_symbols(
    custom_structure_path: str, pwndbg_debug_symbols_output_file: str | None = None
) -> str | None:
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
    gcc_flags = pwndbg.lib.gcc.which(pwndbg.aglib.arch)
    if gcc_compiler_path != "":
        gcc_flags[0] = gcc_compiler_path  # type: ignore[call-overload]

    gcc_cmd = gcc_flags + gcc_extra_flags

    try:
        subprocess.run(gcc_cmd, capture_output=True, check=True)
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


def add_custom_structure(custom_structure_name: str) -> None:
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


def add_structure_from_header(header_file: str, custom_structure_name: str = None) -> None:
    # Properly handle the provided or default name for the custom structure
    custom_structure_name = (
        custom_structure_name.strip()
        if custom_structure_name
        else os.path.splitext(os.path.basename(header_file))[0]
    )

    if not custom_structure_name:
        print(message.error("Invalid structure name provided or generated."))
        return

    pwndbg_custom_structure_path = os.path.join(pwndbg_cachedir, custom_structure_name) + ".c"

    if os.path.exists(pwndbg_custom_structure_path):
        option = input(
            message.notice(f"Structure '{custom_structure_name}' already exists. Overwrite? [y/n] ")
        )
        if option != "y":
            return

    try:
        with open(header_file, "r") as src, open(pwndbg_custom_structure_path, "w") as f:
            content = src.read().strip()
            if not content:
                print(message.notice("Header file is empty, skipping..."))
                return
            f.write(content)
    except (IOError, OSError) as e:
        print(message.error(f"Failed to process header file: {e}"))
        return

    # Avoid checking for file existance. Call the decorator wrapper directly.
    load_custom_structure.__wrapped__(custom_structure_name, pwndbg_custom_structure_path)


@OnlyWhenStructFileExists
def edit_custom_structure(custom_structure_name: str, custom_structure_path: str = "") -> None:
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
    except Exception:
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
def remove_custom_structure(custom_structure_name: str, custom_structure_path: str = "") -> None:
    unload_loaded_symbol(custom_structure_name)
    os.remove(custom_structure_path)
    print(message.success("Symbols are removed!"))


@OnlyWhenStructFileExists
def load_custom_structure(custom_structure_name: str, custom_structure_path: str = "") -> None:
    unload_loaded_symbol(custom_structure_name)
    pwndbg_debug_symbols_output_file = generate_debug_symbols(custom_structure_path)
    if not pwndbg_debug_symbols_output_file:
        return  # generate_debug_symbols prints on failures
    gdb.execute(f"add-symbol-file {pwndbg_debug_symbols_output_file}", to_string=True)
    loaded_symbols[custom_structure_name] = pwndbg_debug_symbols_output_file
    print(message.success("Symbols are loaded!"))


@OnlyWhenStructFileExists
def show_custom_structure(custom_structure_name: str, custom_structure_path: str = "") -> None:
    # Call non-caching version of the function (thus .__wrapped__)
    highlighted_source = pwndbg.pwndbg.commands.context.get_highlight_source.__wrapped__(
        custom_structure_path
    )
    print("\n".join(highlighted_source))


parser = argparse.ArgumentParser(
    description="Add, show, load, edit, or delete custom structures in plain C."
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
    "-f",
    "--file",
    metavar="filepath",
    help="Add a new custom structure from header file",
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


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
def cymbol(add: str, file: str, remove: str, edit: str, load: str, show: str) -> None:
    if add:
        add_custom_structure(add)
    elif file:
        add_structure_from_header(file)
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
