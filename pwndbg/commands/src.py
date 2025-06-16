"""
Diagnostic version of src command to debug boundary detection issues.
File: pwndbg/commands/src_debug.py
"""

from __future__ import annotations

import argparse

import gdb

import pwndbg.commands

# Create the argument parser
parser = argparse.ArgumentParser(description="Debug source display with diagnostics.")

parser.add_argument(
    "-f", "--function", action="store_true", help="Show the entire current function source"
)


@pwndbg.commands.Command(
    parser,
    aliases=["source"],
    category=pwndbg.commands.CommandCategory.CONTEXT,
)
@pwndbg.commands.OnlyWhenRunning
def src_debug(function: bool = False) -> None:
    """Debug version of src to diagnose boundary detection."""

    try:
        # Get current PC
        target_addr = int(gdb.parse_and_eval("$pc"))

        # Get source location
        sal = gdb.find_pc_line(target_addr)
        if not sal.symtab or not sal.line:
            print("No source information available")
            return

        source_file = sal.symtab.fullname()
        current_line = sal.line

        print("Debug Info:")
        print(f"  Address: {target_addr:#x}")
        print(f"  File: {source_file}")
        print(f"  Current line: {current_line}")

        # Try to get function info from GDB
        try:
            block = gdb.block_for_pc(target_addr)
            if block:
                while block and not block.function:
                    block = block.superblock
                if block and block.function:
                    print(f"  Function: {block.function.name}")
                    func_start = int(block.function.value().address)
                    print(f"  Function start address: {func_start:#x}")
                    start_sal = gdb.find_pc_line(func_start)
                    if start_sal and start_sal.line:
                        print(f"  Function start line (from GDB): {start_sal.line}")
        except Exception:
            print("  Function: <unable to determine from debug info>")

        # Read source file
        try:
            with open(source_file, "r") as f:
                source_lines = f.readlines()
        except IOError:
            print(f"Error: Could not read source file: {source_file}")
            return

        if function:
            print("\nAttempting function boundary detection...")

            # Show context around current line first
            print(f"\nContext around line {current_line}:")
            for i in range(max(0, current_line - 5), min(len(source_lines), current_line + 5)):
                marker = ">>>" if i == current_line - 1 else "   "
                print(f"{marker} {i + 1:3d}: {source_lines[i].rstrip()}")

            # Now try to find function boundaries
            print("\nSearching for function start...")

            # Manual search backwards
            for i in range(current_line - 1, max(0, current_line - 20), -1):
                line = source_lines[i]
                if (
                    "(" in line
                    and ")" in line
                    and any(
                        keyword in line for keyword in ["void", "int", "char", "float", "double"]
                    )
                ):
                    print(f"  Potential function start at line {i + 1}: {line.strip()}")
                    if "{" in line or (i + 1 < len(source_lines) and "{" in source_lines[i + 1]):
                        print(f"  -> Confirmed function start at line {i + 1}")

                        # Count braces from here
                        brace_count = 0
                        for j in range(i, len(source_lines)):
                            brace_count += source_lines[j].count("{")
                            brace_count -= source_lines[j].count("}")
                            if brace_count == 0 and source_lines[j].count("}") > 0:
                                print(f"  -> Function end at line {j + 1}")
                                print(f"\nComplete function ({j - i + 1} lines):")
                                for k in range(i, j + 1):
                                    marker = ">>>" if k == current_line - 1 else "   "
                                    print(f"{marker} {k + 1:3d}: {source_lines[k].rstrip()}")
                                return
                        break

            print("\nFailed to detect function boundaries properly")
        else:
            # Just show context
            start_line = max(1, current_line - 10)
            end_line = min(len(source_lines), current_line + 10)

            print(f"\nShowing lines {start_line}-{end_line}:")
            for i in range(start_line - 1, end_line):
                marker = ">>>" if i == current_line - 1 else "   "
                print(f"{marker} {i + 1:3d}: {source_lines[i].rstrip()}")

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
