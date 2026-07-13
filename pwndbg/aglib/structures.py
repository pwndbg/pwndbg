"""
Add, load, show, edit, or delete custom structures.

For the compilation of the structures zig is being used under the hood, unless
`gcc-config-path` is specified.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pwndbg
import pwndbg.lib.tempfile
from pwndbg.aglib import elf
from pwndbg.lib import Status

# Remeber loaded structures. This would be useful for 'remove-symbol-file'.
loaded_structures: dict[str, str] = {}

# Where generated structure source files are saved.
storage_location: Path = pwndbg.lib.tempfile.cachedir("custom-structures")


def compile_structure(struct_path: Path, compiled_path: str | None = None) -> tuple[str, Status]:
    """
    Compile a C file that contains custom struct definitions.

    Zig is being used unless `gcc-config-path` is specified. Naturally
    the compiled output file will have debug info.

    Arguments:
        struct_path: Path to the .c / .h file to compile.
        compiled_path: The path of the output file. If not specified, it will be
            an automatically generated filename in /tmp/.

    Returns:
        A (compiled_path, err) tuple.
    """
    if compiled_path is None:
        _, compiled_path = tempfile.mkstemp(prefix="custom-", suffix=".dbg")

    # -fno-eliminate-unused-debug-types is a handy gcc flag that lets us extract debug info from non-used defined structures.
    compiler_extra_flags = [
        str(struct_path),
        "-c",
        "-g",
        "-fno-eliminate-unused-debug-types",
        "-o",
        compiled_path,
    ]
    err: Status = elf.compile_with_flags(compiler_extra_flags)
    if err.is_failure():
        return "", err

    return compiled_path, Status()


def get_struct_path(name: str) -> Path:
    """
    Get a Path for a name (usually in ~/.cache/pwndbg/custom-structures/).
    """
    return storage_location / f"{name}.c"


def get_struct_path_if_exists(name: str) -> Path | None:
    """
    Get a Path for a name (usually in ~/.cache/pwndbg/custom-structures/) if the
    file exists, otherwise return None.
    """
    path: Path = get_struct_path(name)
    if path.exists():
        return path
    return None


def unload(name: str) -> None:
    """
    Unload structures from the debugger by set name.
    """
    struct_file: str | None = loaded_structures.pop(name, None)
    if struct_file is not None:
        pwndbg.dbg.selected_inferior().remove_symbol_file(struct_file)


def remove(name: str) -> Status:
    """
    Unload structures from the debugger and delete the backing file by set name.
    """
    struct_path: Path | None = get_struct_path_if_exists(name)
    if struct_path is None:
        return Status.fail("No custom structure was found with the given name!")

    unload(name)
    os.unlink(struct_path)
    return Status()


def load_with_path(name: str, struct_path: Path) -> Status:
    """
    Load structures from set name `name`, located at `struct_path` into the debbuger.

    Requires the set to have already been added.
    """
    unload(name)

    outfile, err = compile_structure(struct_path)
    if err.is_failure():
        return err

    pwndbg.dbg.selected_inferior().add_symbol_file(outfile)
    loaded_structures[name] = outfile
    os.unlink(outfile)
    return Status()


def load(name: str) -> Status:
    """
    Load structures from set name `name`.

    Requires the set to have already been added.
    """
    struct_path: Path | None = get_struct_path_if_exists(name)
    if struct_path is None:
        return Status.fail("No custom structure was found with the given name!")

    return load_with_path(name, struct_path)


def saved_names() -> list[str]:
    """
    Returns all set names.
    """
    res: list[str] = []
    for file in os.listdir(storage_location):
        if file.endswith(".c"):
            # Remove the ".c".
            name = os.path.splitext(file)[0]
            res.append(name)
    return res


def create_temp_header_file(content: str) -> Path:
    """
    Creates a temporary file with content `content` and returns the Path to it.
    """
    # We need to use `.c` rather than `.h` because `.h` causes zig/ld.lld to fail compilation:
    # "ld.lld: error: /home/user/.cache/zig/o/81a692b354ebabc64d08698dff966d67/page_structs.o: unknown file type"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".c") as tmp_file:
        tmp_file.write(content.encode())
        return Path(tmp_file.name)


def add(name: str, content: str) -> Status:
    """
    Add structures defined in `content` (C code) by reference structure set name `name` and load
    them into the debugger.

    If a `name` structure set file already exists, it will be overwritten.

    The name will be prefixed with `_internal_` to separate from user-defined structures.
    """
    struct_path: Path = get_struct_path("_internal_" + name)
    # We don't care if it existed before.
    with open(struct_path, "w") as f:
        f.write(content)
    err = load_with_path(name, struct_path)
    return err
