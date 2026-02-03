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
import pwndbg.aglib.elf as elf
import pwndbg.lib.tempfile
from pwndbg.lib import Status

# Remeber loaded structures. This would be useful for 'remove-symbol-file'.
loaded_structures: dict[str, str] = {}

# Where generated symbol source files are saved.
pwndbg_cachedir: Path = pwndbg.lib.tempfile.cachedir("custom-symbols")


def generate_debug_symbols(
    custom_structure_path: Path, pwndbg_debug_symbols_output_file: str | None = None
) -> tuple[str, Status]:
    if not pwndbg_debug_symbols_output_file:
        _, pwndbg_debug_symbols_output_file = tempfile.mkstemp(prefix="custom-", suffix=".dbg")

    # -fno-eliminate-unused-debug-types is a handy gcc flag that lets us extract debug symbols from non-used defined structures.
    compiler_extra_flags = [
        str(custom_structure_path),
        "-c",
        "-g",
        "-fno-eliminate-unused-debug-types",
        "-o",
        pwndbg_debug_symbols_output_file,
    ]
    err: Status = elf.compile_with_flags(compiler_extra_flags)
    if err.is_failure():
        return "", err

    return pwndbg_debug_symbols_output_file, Status()


def get_struct_path(name: str) -> Path:
    return pwndbg_cachedir / f"{name}.c"


def get_struct_path_if_exists(name: str) -> Path | None:
    path: Path = get_struct_path(name)
    if path.exists():
        return path
    return None


def unload(name: str) -> None:
    struct_file = loaded_structures.get(name)
    if struct_file is not None:
        pwndbg.dbg.selected_inferior().remove_symbol_file(struct_file)
        loaded_structures.pop(name)


def remove(name: str) -> Status:
    struct_path: Path | None = get_struct_path_if_exists(name)
    if struct_path is None:
        return Status.fail("No custom structure was found with the given name!")

    unload(name)
    os.unlink(struct_path)
    return Status()


def load_with_path(name: str, struct_path: Path) -> Status:
    unload(name)

    pwndbg_debug_symbols_output_file, err = generate_debug_symbols(struct_path)
    if err.is_failure():
        return err

    pwndbg.dbg.selected_inferior().add_symbol_file(pwndbg_debug_symbols_output_file)
    loaded_structures[name] = pwndbg_debug_symbols_output_file
    os.unlink(pwndbg_debug_symbols_output_file)
    return Status()


def load(name: str) -> Status:
    struct_path: Path | None = get_struct_path_if_exists(name)
    if struct_path is None:
        return Status.fail("No custom structure was found with the given name!")

    return load_with_path(name, struct_path)


def saved_names() -> list[str]:
    res: list[str] = []
    for file in os.listdir(pwndbg_cachedir):
        if file.endswith(".c"):
            # Remove the ".c".
            name = os.path.splitext(file)[0]
            res.append(name)
    return res


def create_temp_header_file(content: str) -> Path:
    """Create a temporary header file with the given content."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".h") as tmp_file:
        tmp_file.write(content.encode())
        return Path(tmp_file.name)


def add(name: str, content: str, unlink_now: bool) -> Status:
    struct_path = create_temp_header_file(content)
    err = load_with_path(name, struct_path)
    if unlink_now:
        os.unlink(struct_path)
    return err
