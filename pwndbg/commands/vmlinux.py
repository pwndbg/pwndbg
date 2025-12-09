"""
Loads a bzImage or vmlinux file to add kernel debug symbols. This command uses vmlinux-to-elf
to extract the ELF file from a bzImage and then loads it with the kernel base address.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tempfile

import pwndbg.aglib.kernel
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.dbg
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Load bzImage or vmlinux file to add kernel debug symbols."
)
parser.add_argument(
    "filepath",
    type=str,
    help="Path to the bzImage or vmlinux file to load",
)
parser.add_argument(
    "-t",
    "--tool",
    type=str,
    help="Path to the vmlinux-to-elf tool (if not in PATH)",
)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWhenPagingEnabled
def vmlinux(filepath: str, tool: str = None) -> None:
    # Verify the input file exists
    if not os.path.isfile(filepath):
        print(M.error(f"File not found: {filepath}"))
        return

    # Get the kernel base address
    base = pwndbg.aglib.kernel.arch_paginginfo().kbase
    if base is None:
        print(M.error("Unable to locate the kernel base address"))
        return

    print(M.success(f"Found kernel base address: {hex(base)}"))

    # Find vmlinux-to-elf tool
    if tool:
        # User specified the tool path
        vmlinux_tool = tool
        if not os.path.isfile(vmlinux_tool):
            print(M.error(f"Specified tool not found: {vmlinux_tool}"))
            return
        if not os.access(vmlinux_tool, os.X_OK):
            print(M.error(f"Specified tool is not executable: {vmlinux_tool}"))
            return
    else:
        # GDB may not inherit the full PATH, so check common locations
        vmlinux_tool = shutil.which("vmlinux-to-elf")
        if not vmlinux_tool:
            # Check common user install locations
            common_paths = [
                os.path.expanduser("~/.local/bin/vmlinux-to-elf"),
                "/usr/local/bin/vmlinux-to-elf",
                "/usr/bin/vmlinux-to-elf",
            ]
            for path in common_paths:
                if os.path.isfile(path) and os.access(path, os.X_OK):
                    vmlinux_tool = path
                    break

        if not vmlinux_tool:
            print(
                M.error(
                    "vmlinux-to-elf tool not found in PATH or common locations.\n"
                    "Please install it or ensure it's in: ~/.local/bin, /usr/local/bin, or /usr/bin\n"
                    "You can install it with: pip install --user vmlinux-to-elf\n"
                    "Or specify the tool path with: vmlinux <filepath> --tool <path-to-vmlinux-to-elf>"
                )
            )
            return

    # Create a temporary file for the extracted ELF
    with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as tmpfile:
        tmpfile_path = tmpfile.name

    try:
        # Run vmlinux-to-elf to extract the ELF file
        print(f"Extracting ELF from {filepath} using vmlinux-to-elf...")
        result = subprocess.run(
            [vmlinux_tool, filepath, tmpfile_path],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            print(M.error(f"vmlinux-to-elf failed with error:\n{result.stderr}"))
            return

        print(M.success(f"Successfully extracted ELF to {tmpfile_path}"))

        # Add the symbol file with the kernel base address
        print(f"Loading symbols at address {hex(base)}...")
        pwndbg.dbg.selected_inferior().add_symbol_file(tmpfile_path, base)
        print(M.success(f"Loaded kernel symbols from {filepath} successfully"))

    except FileNotFoundError:
        print(
            M.error(
                "vmlinux-to-elf tool not found. Please ensure it is installed and in your PATH."
            )
        )
    except Exception as e:
        print(M.error(f"Error loading symbols: {str(e)}"))
    finally:
        # Note: We don't delete the temp file here because GDB needs it to remain accessible
        # for as long as the debugging session is active
        pass
