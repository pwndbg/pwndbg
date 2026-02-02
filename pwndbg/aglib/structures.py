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


def get_struct_path_if_exist(name: str) -> Path | None:
    pwndbg_custom_structure_path: Path = pwndbg_cachedir / f"{name}.c"
    if pwndbg_custom_structure_path.exists():
        return pwndbg_custom_structure_path
    return None


def create_temp_header_file(content: str) -> str:
    """Create a temporary header file with the given content."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".h") as tmp_file:
        tmp_file.write(content.encode())
        return tmp_file.name


def unload(name: str) -> None:
    custom_structure_symbols_file = loaded_structures.get(name)
    if custom_structure_symbols_file is not None:
        pwndbg.dbg.selected_inferior().remove_symbol_file(custom_structure_symbols_file)
        loaded_structures.pop(name)


def remove(name: str) -> Status:
    struct_path: Path | None = get_struct_path_if_exist(name)
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
    struct_path: Path | None = get_struct_path_if_exist(name)
    if struct_path is None:
        return Status.fail("No custom structure was found with the given name!")

    return load_with_path(name, struct_path)
