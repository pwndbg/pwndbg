"""
Add, load, show, edit, or delete symbols for custom structures.

For the generation of the symbols g++/gcc is being used under the hood.

In case of remote debugging a binary which is not native to your architecture it
is advised to configure the 'gcc-config-path' config parameter to your own cross-platform
gnu gcc compiled toolchain for your target architecture.

You are advised to configure the 'cymbol-editor' config parameter to the path of your
favorite text editor. Otherwise cymbol expands $EDITOR and $VISUAL environment variables
to find the path to the default text editor.
"""

from __future__ import annotations

import argparse
import functools
import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from typing_extensions import ParamSpec

import pwndbg
import pwndbg.aglib.structures
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.lib.config
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib import Status

P = ParamSpec("P")
T = TypeVar("T")

cymbol_editor = pwndbg.config.add_param(
    "cymbol-editor",
    "",
    "path to the editor for editing custom structures",
    param_class=pwndbg.lib.config.PARAM_OPTIONAL_FILENAME,
)


def OnlyWhenStructFileExists(func: Callable[[str, Path], Status]) -> Callable[[str], Status]:
    """
    Takes a structure name, and if it exists, passes the name with the path to the wrapped function.

    If it doesn't, returns a Status with the error message and the NO_STRUCTURE_FILE error code.
    """

    @functools.wraps(func)
    def wrapper(custom_structure_name: str) -> Status:
        return func(custom_structure_name, pwndbg_custom_structure_path)

    return wrapper


def add_custom_structure(custom_structure_name: str, force: bool = False):
    pwndbg_custom_structure_path = pwndbg_cachedir / f"{custom_structure_name}.c"

    if pwndbg_custom_structure_path.exists() and not force:
        option = input(
            message.notice(
                "A custom structure was found with the given name, would you like to overwrite it? [y/N] "
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


def add_structure_from_header(
    header_file: str, custom_structure_name: str | None = None, force: bool = False
) -> None:
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
        if not force:
            option = input(
                message.notice(
                    f"Structure '{custom_structure_name}' already exists. Overwrite? [y/N] "
                )
            )
            if option.lower() != "y":
                print(message.notice("Aborted by user."))
                return

    try:
        with open(header_file) as src, open(pwndbg_custom_structure_path, "w") as f:
            content = src.read().strip()
            if not content:
                print(message.notice("Header file is empty, skipping..."))
                return
            f.write(content)
    except OSError as e:
        print(message.error(f"Failed to process header file: {e}"))
        return

    load_custom_structure.__wrapped__(custom_structure_name, pwndbg_custom_structure_path)


def load(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exist(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    err = pwndbg.aglib.structures.load_with_path(name, struct_path)
    if err.is_failure():
        print(message.error(err.message))
    else:
        print(message.success(f"Loaded custom symbols! (from {struct_path})"))


def edit(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exist(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    # Lookup an editor to use for editing the custom structure.
    editor_preference = os.getenv("EDITOR")
    if not editor_preference:
        editor_preference = os.getenv("VISUAL")
    if not editor_preference:
        editor_preference = "vi"

    if cymbol_editor != "":
        editor_preference = str(cymbol_editor)

    try:
        subprocess.run(
            [editor_preference, struct_path],
            check=True,
        )
    except Exception:
        print(message.error("An error occurred during opening the source file."))
        print(message.error(f"Path to the custom structure: {struct_path}"))
        print(message.error("Please try to manually edit the structure."))
        print(
            message.error(
                '\nTry to set a path to an editor with:\n\tset "cymbol-editor" /usr/bin/nano'
            )
        )
        return

    input(message.notice("Press enter when finished editing."))

    load(name)


def remove(name: str) -> None:
    err: Status = pwndbg.aglib.structures.remove(name)
    if err.is_success():
        print(message.success("Symbols are removed!"))
    else:
        print(message.error(err.message))


def show_custom_structure(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exist(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    # Call non-caching version of the function
    highlighted_source = pwndbg.commands.context.get_highlight_source_uncached(
        str(struct_path)
    )
    print("\n".join(highlighted_source))


parser = argparse.ArgumentParser(
    description="""
Add custom C structures to the debugger.

Unless you specify `gcc-compiler-path`, zig is used under to hood to compile the C files to
whichever target architecture you are currently debugging.
"""
)

subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

add_parser = subparsers.add_parser(
    "add", help="Add a custom structure", description="Add a custom structure."
)
add_parser.add_argument("name", help="Name of custom structure", type=str)
add_parser.add_argument(
    "--force", action="store_true", help="Overwrite if structure already exists"
)

remove_parser = subparsers.add_parser(
    "remove", help="Remove a custom structure", description="Remove a custom structure."
)
remove_parser.add_argument("name", help="Name of custom structure", type=str)

edit_parser = subparsers.add_parser(
    "edit", help="Edit a custom structure", description="Edit a custom structure."
)
edit_parser.add_argument("name", help="Name of custom structure", type=str)

load_parser = subparsers.add_parser(
    "load", help="Load a custom structure", description="Load a custom structure."
)
load_parser.add_argument("name", help="Name of custom structure", type=str)

show_parser = subparsers.add_parser(
    "show", help="Show a custom structure", description="Show a custom structure."
)
show_parser.add_argument("name", help="Name of custom structure", type=str)

file_parser = subparsers.add_parser(
    "file",
    help="Add a structure from a header file",
    description="Add a structure from a header file.",
)
file_parser.add_argument("path", help="Path to header file", type=str)
file_parser.add_argument("--name", help="Optional structure name", type=str)
file_parser.add_argument("--force", action="store_true", help="Overwrite if exists")

show_all_parser = subparsers.add_parser(
    "show-all", help="Show all stored structures", description="Show all stored structures."
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MISC,
    notes="""
If a loaded structure defines a symbol that already exists, the debugger may prefer the
original type or behave unexpectedly. It’s recommended to use unique struct names to avoid
type conflicts.
""",
    examples="""
> cymbol file --force ./structs.h
Having something like this in your folder-local `.gdbinit` can be handy.
""",
)
def cymbol(
    subcommand: str | None = None,
    name: str | None = None,
    path: str | None = None,
    force=False,
):
    match subcommand:
        case "add":
            assert name is not None
            add_custom_structure(name, force=force)
        case "remove":
            assert name is not None
            remove(name)
        case "edit":
            assert name is not None
            edit(name)
        case "load":
            assert name is not None
            load(name)
        case "file":
            assert path is not None
            add_structure_from_header(path, name, force=force)
        case "show":
            assert name is not None
            show_custom_structure(name)
        case "show-all":
            print(message.notice("Available custom structure names:\n"))
            for file in os.listdir(pwndbg_cachedir):
                if file.endswith(".c"):
                    name = os.path.splitext(file)[0]
                    print(f"  - {name}")
        case _:
            parser.print_help()
