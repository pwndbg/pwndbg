"""
Add, load, show, edit, or delete custom structures.

For the compilation of the structures zig is being used under the hood, unless
`gcc-config-path` is specified.

You are advised to configure the 'cymbol-editor' config parameter to the path of your
favorite text editor. Otherwise cymbol expands $EDITOR and $VISUAL environment variables
to find the path to the default text editor.
"""

from __future__ import annotations

import argparse
import os
import subprocess
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


def get_editor() -> str:
    if str(cymbol_editor) == "":
        # Lookup an editor to use for editing the a structure.
        editor: str | None = os.getenv("EDITOR")
        if editor is None:
            editor = os.getenv("VISUAL")
        if editor is None:
            editor = "vi"
    else:
        # Use the specified editor.
        editor = str(cymbol_editor)
    return editor


def run_editor_on_file(filepath: Path) -> bool:
    try:
        subprocess.run(
            [get_editor(), str(filepath)],
            check=True,
        )
    except Exception:
        print(message.error("An error occurred during opening the source file."))
        print(message.error(f"Path to the structure: {filepath}"))
        print(message.error("Please try to manually edit the structure."))
        print(
            message.hint(
                '\nTry to set a path to an editor with:\n\tset "cymbol-editor" /usr/bin/nano'
            )
        )
        return False

    input(message.notice("Press enter when finished."))
    return True


def _edit_and_load(name: str, struct_path: Path, preamble: str = "") -> None:
    if not run_editor_on_file(struct_path):
        return

    # Check that the user actually input something.
    with open(struct_path) as f:
        data: str = f.read().strip()
        if data == preamble.strip() or data == "":
            print(message.warn("Empty file, skipping..."))
            return

    print(message.success("Saved"), end="")

    err: Status = pwndbg.aglib.structures.load_with_path(name, struct_path)
    if err.is_success():
        print(message.success(" and loaded!"))
    else:
        print(message.error(" but failed loading."))
        print(message.error(err.message))


def add(name: str, force: bool) -> None:
    struct_path = pwndbg.aglib.structures.get_struct_path(name)
    if struct_path.exists() and not force:
        option = input(
            message.notice(
                "A custom structure was found with the given name, would you like to overwrite it? [y/N] "
            )
        )
        if option.lower() != "y":
            print(message.notice("Aborted by user."))
            return

    preamble = "// Enter your structure in a C header style.\n"
    preamble += f"// Refer to this structure file as '{name}'.\n"

    with open(struct_path, "w") as f:
        f.write(preamble)

    _edit_and_load(name, struct_path, preamble)


def add_from_header(header_file: str, name: str | None, force: bool, quiet: bool) -> None:
    if name is None:
        name = os.path.splitext(os.path.basename(header_file))[0]
    name = name.strip()

    if name == "":
        print(message.error("Invalid structure name provided or generated."))
        return

    struct_path: Path = pwndbg.aglib.structures.get_struct_path(name)
    if struct_path.exists():
        if not force:
            option = input(message.notice(f"Structure '{name}' already exists. Overwrite? [y/N] "))
            if option.lower() != "y":
                print(message.notice("Aborted by user."))
                return

    try:
        with open(header_file) as src, open(struct_path, "w") as f:
            content = src.read().strip()
            if not content:
                print(message.notice("Header file is empty, skipping..."))
                return
            f.write(content)
            if not quiet:
                print(message.success("Saved"), end="")
    except OSError as e:
        print(message.error(f"Failed to process header file: {e}"))
        return

    err: Status = pwndbg.aglib.structures.load_with_path(name, struct_path)
    if err.is_success():
        if not quiet:
            print(message.success(" and loaded!"))
    else:
        print(".\n" + err.message)


def load(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exists(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    err = pwndbg.aglib.structures.load_with_path(name, struct_path)
    if err.is_failure():
        print(message.error(err.message))
    else:
        print(message.success(f"Loaded custom structs! (from {struct_path})"))


def edit(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exists(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    _edit_and_load(name, struct_path)


def remove(name: str) -> None:
    err: Status = pwndbg.aglib.structures.remove(name)
    if err.is_success():
        print(message.success("Structs are removed!"))
    else:
        print(message.error(err.message))


def show(name: str) -> None:
    struct_path: Path | None = pwndbg.aglib.structures.get_struct_path_if_exists(name)
    if struct_path is None:
        print(message.error("No custom structure was found with the given name!"))
        return

    # Call non-caching version of the function
    highlighted_source = pwndbg.commands.context.get_highlight_source_uncached(str(struct_path))
    print("\n".join(highlighted_source))


def show_all() -> None:
    print(message.notice("Available custom structure names:\n"))
    names: list[str] = pwndbg.aglib.structures.saved_names()
    for name in names:
        if not name.startswith("_internal_"):
            print(f"  - {name}")
    for name in names:
        if name.startswith("_internal_"):
            print(f"  - {name}")


parser = argparse.ArgumentParser(
    description="""
Add custom C structures to the debugger.

Unless you specify `gcc-compiler-path`, zig is used under to hood to compile the C files to
whichever target architecture you are currently debugging.
"""
)

subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")
subparsers.required = True

add_parser = subparsers.add_parser(
    "add",
    help="Add a custom structure and load it into the debugger",
    description="Add a custom structure and load it into the debugger.",
)
add_parser.add_argument("name", help="Name of custom structure", type=str)
add_parser.add_argument(
    "--force", action="store_true", help="Overwrite if structure already exists"
)

remove_parser = subparsers.add_parser(
    "remove",
    help="Remove a custom structure and unload it from the debugger",
    description="Remove a custom structure and unload it from the debugger.",
)
remove_parser.add_argument("name", help="Name of custom structure", type=str)

edit_parser = subparsers.add_parser(
    "edit",
    help="Edit a custom structure and reload it",
    description="Edit a custom structure and reload it.",
)
edit_parser.add_argument("name", help="Name of custom structure", type=str)

load_parser = subparsers.add_parser(
    "load",
    help="Load a previously added structure into the debugger",
    description="Load a previously added custom structure into the debugger.",
)
load_parser.add_argument("name", help="Name of custom structure", type=str)

show_parser = subparsers.add_parser(
    "show", help="Show a structure's definition", description="Show a structure's definition."
)
show_parser.add_argument("name", help="Name of custom structure", type=str)

file_parser = subparsers.add_parser(
    "file",
    help="Add and load a structure from a header file",
    description="Add and load a structure from a header file.",
)
file_parser.add_argument("path", help="Path to header file", type=str)
file_parser.add_argument("--name", help="Optional structure name", type=str)
file_parser.add_argument("--force", action="store_true", help="Overwrite if exists")
file_parser.add_argument(
    "--quiet", action="store_true", help="Do not output any message on success"
)

show_all_parser = subparsers.add_parser(
    "show-all",
    help="Show the names of all stored structures",
    description="Show the names of all stored (i.e. previusly added) structures.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MISC,
    notes=f"""
If a loaded structure defines a type that already exists, the debugger may prefer the
original type or behave unexpectedly. It’s recommended to use unique struct names to avoid
type conflicts.

Added structures are saved in {pwndbg.aglib.structures.storage_location}/.
""",
    examples="""
> cymbol file --force --quiet ./structs.h
Having something like this in your folder-local `.gdbinit` can be handy.
""",
)
def cymbol(
    subcommand: str,
    name: str = "",
    path: str = "",
    force: bool = False,
    quiet: bool = False,
) -> None:
    match subcommand:
        case "add":
            add(name, force)
        case "remove":
            remove(name)
        case "edit":
            edit(name)
        case "load":
            load(name)
        case "file":
            add_from_header(path, name, force, quiet)
        case "show":
            assert name is not None
            show(name)
        case "show-all":
            show_all()
