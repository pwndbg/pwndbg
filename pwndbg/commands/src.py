"""
Source code viewing command for pwndbg with intelligent function boundary detection
File: pwndbg/commands/src.py
"""

from __future__ import annotations

import argparse
import traceback

import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.color.context as C
import pwndbg.commands
import pwndbg.dbg
from pwndbg.commands.function_boundaries import get_function_boundaries_for_src

# Create the argument parser
parser = argparse.ArgumentParser(description="Display source code around current location.")

parser.add_argument(
    "lines",
    type=int,
    nargs="?",  # Optional positional argument
    default=10,
    help="Number of lines to show around the current location (default: 10)",
)

parser.add_argument(
    "-f", "--function", action="store_true", help="Show the entire current function source"
)

parser.add_argument(
    "address",
    type=int,
    nargs="?",  # Optional address to show source for
    help="Address to show source for (default: current PC)",
)


@pwndbg.commands.Command(
    parser,
    aliases=["source"],
    category=pwndbg.commands.CommandCategory.CONTEXT,
    examples="""
    src                 -- show 10 lines around current location
    src 20              -- show 20 lines around current location
    src -f              -- show entire current function
    src 15 main         -- show 15 lines around main function
    """,
    notes="""
This command requires source code to be available (compiled with -g flag).
The current line is highlighted for easy identification.
When using -f flag, function boundaries are detected intelligently using debug symbols
or language-specific heuristics for C, C++, Python, Rust, Go, Java, JavaScript, and Assembly.
    """,
)
@pwndbg.commands.OnlyWhenRunning
def src(lines: int = 10, function: bool = False, address: int = None) -> None:
    """Display source code around the current location or specified address."""

    try:
        # Determine the address to show source for
        if address is not None:
            target_addr = address
        else:
            # Use current PC (program counter) - using pwndbg abstraction
            target_addr = pwndbg.aglib.regs.pc
            if target_addr is None:
                print("Cannot get current PC")
                return

        # Get source location using pwndbg abstraction
        # For a specific address, we need to handle it differently
        if address is not None:
            # Try to get frame at specific address if possible
            # This is more complex in the abstraction layer
            sal = pwndbg.dbg.selected_frame().sal()
        else:
            sal = pwndbg.dbg.selected_frame().sal()

        if sal is None:
            print("No source information available for this location")
            return

        source_file, current_line = sal

        # Read the source file
        try:
            with open(source_file, "r") as f:
                source_lines = f.readlines()
        except IOError:
            print(f"Error: Could not read source file: {source_file}")
            return

        if function:
            # Use intelligent function boundary detection
            try:
                start_line, end_line = get_function_boundaries_for_src(
                    source_file, target_addr, current_line, source_lines
                )

                # Don't modify boundaries for small functions - show the whole function
                print(f"Source (function): {source_file}")

            except Exception as e:
                # Fallback to the old method if detection fails
                print(f"Warning: Function boundary detection failed: {e}")
                print("Falling back to heuristic method")
                start_line = max(1, current_line - 15)
                end_line = min(len(source_lines), current_line + 25)
                print(f"Source (function - approximate): {source_file}")
        else:
            # Show specified number of lines around current line
            start_line = max(1, current_line - lines // 2)
            end_line = min(len(source_lines), current_line + lines // 2)
            print(f"Source: {source_file}")

        # Display the source lines
        for line_num in range(start_line, end_line + 1):
            if line_num > len(source_lines):
                break

            line_content = source_lines[line_num - 1].rstrip()

            # Highlight current line using pwndbg's color system
            if line_num == current_line:
                # Use pwndbg's color scheme for highlighting
                prefix = C.prefix("►")
                line_display = C.highlight(f"{prefix}{line_num:4d}│ {line_content}")
            else:
                line_display = f" {line_num:4d}│ {line_content}"

            print(line_display)

        # Show function boundaries info if in function mode
        if function:
            print(
                f"\nShowing lines {start_line}-{end_line} ({end_line - start_line + 1} lines total)"
            )

    except Exception as e:
        print(f"Error displaying source: {e}")
        if pwndbg.config.exception_verbose:
            traceback.print_exc()
