"""
Function boundary detection for pwndbg source viewing.
Supports multiple programming languages through debug symbols and heuristics.
"""

from __future__ import annotations

import os
import re
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import gdb


class Language(Enum):
    C = "c"
    CPP = "cpp"
    RUST = "rust"
    GO = "go"
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    ASSEMBLY = "assembly"
    UNKNOWN = "unknown"


class FunctionBoundaryDetector:
    """Detects function boundaries using GDB debug info and language heuristics."""

    def __init__(self):
        # Language detection patterns based on file extensions
        self.extension_map = {
            ".c": Language.C,
            ".h": Language.C,
            ".cpp": Language.CPP,
            ".cc": Language.CPP,
            ".cxx": Language.CPP,
            ".hpp": Language.CPP,
            ".rs": Language.RUST,
            ".go": Language.GO,
            ".py": Language.PYTHON,
            ".java": Language.JAVA,
            ".js": Language.JAVASCRIPT,
            ".s": Language.ASSEMBLY,
            ".asm": Language.ASSEMBLY,
        }

        # Language-specific patterns for function detection
        self.patterns: Dict[Language, Dict[str, Any]] = {
            Language.C: {
                "start": [
                    # Standard function definition
                    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    # Static/inline functions
                    r"^(?:static|inline|extern)\s+[\w\s\*]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    # Function with attributes
                    r"^[\w\s\*]+\s+(__attribute__\s*\([^)]+\)\s*)?([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                ],
                "end": r"^}",
                "continuation": r"^\s*{",  # Opening brace on next line
            },
            Language.CPP: {
                "start": [
                    # Class methods
                    r"^(?:[\w\s]*::)?([a-zA-Z_]\w*)\s*\([^)]*\)(?:\s*const)?\s*(?:override|final)?\s*{",
                    # Templates
                    r"^template\s*<[^>]*>\s*[\w\s\*]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    # Constructors/destructors
                    r"^([a-zA-Z_]\w*)::\1\s*\([^)]*\)\s*(?::[^{]+)?\s*{",
                    r"^([a-zA-Z_]\w*)::~\1\s*\([^)]*\)\s*{",
                    # Standard functions (similar to C)
                    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                ],
                "end": r"^}",
                "continuation": r"^\s*{",
            },
            Language.RUST: {
                "start": [
                    # Function definitions
                    r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]+"\s+)?)?fn\s+([a-zA-Z_]\w*)',
                    # Methods
                    r"^\s*(?:pub(?:\([^)]+\))?\s+)?fn\s+([a-zA-Z_]\w*)\s*\(",
                    # Closures (limited support)
                    r"^\s*let\s+([a-zA-Z_]\w*)\s*=\s*\|[^|]*\|\s*{",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.GO: {
                "start": [
                    # Function definitions
                    r"^func\s+([a-zA-Z_]\w*)\s*\(",
                    # Methods
                    r"^func\s+\([^)]+\)\s+([a-zA-Z_]\w*)\s*\(",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.PYTHON: {
                "start": [
                    # Function/method definitions
                    r"^(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(",
                    # Class definitions (treat as functions for boundary detection)
                    r"^class\s+([a-zA-Z_]\w*)",
                ],
                "end": None,  # Python uses indentation
                "indent_based": True,
            },
            Language.JAVA: {
                "start": [
                    # Method definitions with modifiers
                    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*[\w<>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*{",
                    # Constructors
                    r"^\s*(?:public|private|protected)\s+([A-Z]\w*)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*{",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.JAVASCRIPT: {
                "start": [
                    # Function declarations
                    r"^(?:async\s+)?function\s+([a-zA-Z_$][\w$]*)\s*\(",
                    # Methods in classes
                    r"^\s*(?:async\s+)?([a-zA-Z_$][\w$]*)\s*\([^)]*\)\s*{",
                    # Arrow functions assigned to variables
                    r"^\s*(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>",
                ],
                "end": r"^}",
                "continuation": r"{\s*$|=>\s*{\s*$",
            },
            Language.ASSEMBLY: {
                "start": [
                    # Label-based function start
                    r"^([a-zA-Z_]\w*):\s*$",
                    # .global directive
                    r"^\s*\.glob[a]?l\s+([a-zA-Z_]\w*)",
                ],
                "end": [
                    r"^\s*ret\s*$",
                    r"^\s*retn\s*$",
                    r"^\s*jmp\s+",  # Tail call
                    r"^([a-zA-Z_]\w*):\s*$",  # Next function
                ],
                "special": True,
            },
        }

    def detect_language(self, filename: str) -> Language:
        """Detect language from filename extension."""
        ext = os.path.splitext(filename)[1].lower()
        return self.extension_map.get(ext, Language.UNKNOWN)

    def get_function_boundaries_from_gdb(self, address: int) -> Optional[Tuple[int, int, str]]:
        """
        Try to get function boundaries using GDB's debug information.
        Returns (start_line, end_line, function_name) or None.
        """
        try:
            # Get the block containing the address
            block = gdb.block_for_pc(address)
            if not block:
                return None

            # Find the function block
            while block and not block.function:
                block = block.superblock

            if not block or not block.function:
                return None

            func = block.function
            func_name = func.name

            # Get the symbol for line information
            sym = func.value()
            if not sym:
                return None

            # Get start and end addresses of the function
            try:
                start_addr = int(sym.address)
                # Try to get the size/end from the symbol
                size = sym.type.sizeof
                if size and size > 0:
                    end_addr = start_addr + size
                else:
                    # Fallback: use block boundaries
                    end_addr = int(block.end)
            except Exception:
                return None

            # Convert addresses to line numbers
            start_sal = gdb.find_pc_line(start_addr)
            end_sal = gdb.find_pc_line(end_addr - 1)  # -1 to get last instruction

            if start_sal.line and end_sal.line:
                return (start_sal.line, end_sal.line, func_name)

        except Exception:
            # Debug symbols might not be available
            pass

        return None

    def find_function_boundaries_heuristic(
        self, lines: List[str], current_line: int, language: Language
    ) -> Tuple[int, int]:
        """
        Find function boundaries using language-specific heuristics.
        Returns (start_line, end_line) as 1-based indices.
        """
        if language not in self.patterns:
            # Fallback for unknown languages
            return self._default_boundaries(lines, current_line)

        pattern_info = self.patterns[language]

        # Special handling for Python (indentation-based)
        if pattern_info.get("indent_based"):
            return self._find_python_boundaries(lines, current_line)

        # Special handling for Assembly
        if pattern_info.get("special") and language == Language.ASSEMBLY:
            return self._find_assembly_boundaries(lines, current_line)

        # For brace-based languages
        return self._find_brace_boundaries(lines, current_line, pattern_info)

    def _find_brace_boundaries(
        self,
        lines: List[str],
        current_line: int,
        pattern_info: Dict[str, Any],
    ) -> Tuple[int, int]:
        """Find boundaries for brace-based languages (C, C++, Java, etc.)."""
        start_patterns = pattern_info["start"]

        # Convert to 0-based indexing
        current_idx = current_line - 1

        # Step 1: Find function start by searching backwards
        start_idx = current_idx
        found_start = False

        for i in range(current_idx, -1, -1):
            line = lines[i]

            # Check each pattern
            for pattern in start_patterns:
                if re.match(pattern, line):
                    # Found a potential function start
                    # Look for the opening brace
                    if "{" in line:
                        start_idx = i
                        found_start = True
                        break
                    # Check next few lines for opening brace
                    for j in range(i, min(i + 3, len(lines))):
                        if "{" in lines[j]:
                            start_idx = i
                            found_start = True
                            break
                    if found_start:
                        break
            if found_start:
                break

        # If we didn't find a clear function start, look for any line with a brace
        # that might be a function (has parentheses before it)
        if not found_start:
            for i in range(current_idx, -1, -1):
                line = lines[i]
                if "{" in line and "(" in line and ")" in line:
                    start_idx = i
                    break
                if i > 0 and "{" in line:
                    # Check if previous line has function signature
                    prev_line = lines[i - 1]
                    if "(" in prev_line and ")" in prev_line:
                        start_idx = i - 1
                        break

        # Step 2: Count braces from the start to find the end
        brace_count = 0
        end_idx = start_idx
        found_opening = False

        for i in range(start_idx, len(lines)):
            line = lines[i]

            # Simple comment stripping
            if "//" in line:
                line = line[: line.index("//")]

            # Count braces character by character
            for char in line:
                if char == "{":
                    brace_count += 1
                    found_opening = True
                elif char == "}":
                    brace_count -= 1

                    # Function ends when braces balance back to 0
                    if found_opening and brace_count == 0:
                        end_idx = i
                        # Convert back to 1-based indexing
                        return (start_idx + 1, end_idx + 1)

        # If we couldn't find a proper end, estimate it
        if end_idx == start_idx:
            # Look for the next function or end of file
            for i in range(current_idx + 1, len(lines)):
                line = lines[i]
                # Check if this might be the start of another function
                for pattern in start_patterns:
                    if re.match(pattern, line):
                        end_idx = i - 1
                        return (start_idx + 1, end_idx + 1)
            # Otherwise, include up to 50 lines or end of file
            end_idx = min(start_idx + 50, len(lines) - 1)

        return (start_idx + 1, end_idx + 1)

    def _find_python_boundaries(self, lines: List[str], current_line: int) -> Tuple[int, int]:
        """Find boundaries for Python functions using indentation."""
        if not lines:
            return (1, 1)

        # Get the indentation level of the current line
        current_indent = len(lines[current_line - 1]) - len(lines[current_line - 1].lstrip())

        # Search backward for function/class definition
        start_line = current_line
        for i in range(current_line - 1, -1, -1):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Check for function/class definition
            if re.match(r"^(?:async\s+)?def\s+\w+|^class\s+\w+", line):
                start_line = i + 1
                break

            # If we hit a line with less indentation, we've gone too far
            line_indent = len(line) - len(line.lstrip())
            if line_indent < current_indent and stripped:
                break

        # Search forward for end of function
        end_line = current_line
        base_indent = len(lines[start_line - 1]) - len(lines[start_line - 1].lstrip())

        for i in range(current_line, len(lines)):
            line = lines[i]
            stripped = line.strip()

            # Skip empty lines
            if not stripped:
                continue

            # Check indentation
            line_indent = len(line) - len(line.lstrip())
            if line_indent <= base_indent and i > start_line:
                end_line = i
                break
        else:
            end_line = len(lines)

        return (start_line, end_line)

    def _find_assembly_boundaries(self, lines: List[str], current_line: int) -> Tuple[int, int]:
        """Find boundaries for assembly functions."""
        # Search backward for function label or .global
        start_line = current_line
        for i in range(current_line - 1, -1, -1):
            line = lines[i].strip()
            if re.match(r"^[a-zA-Z_]\w*:\s*$", line) or re.match(r"^\s*\.glob[a]?l\s+", line):
                start_line = i + 1
                break

        # Search forward for ret or next function
        end_line = current_line
        for i in range(current_line, len(lines)):
            line = lines[i].strip()
            if (
                re.match(r"^\s*ret\s*$", line)
                or re.match(r"^\s*retn\s*$", line)
                or (i > current_line and re.match(r"^[a-zA-Z_]\w*:\s*$", line))
            ):
                end_line = i + 1
                break

        return (start_line, end_line)

    def _default_boundaries(self, lines: List[str], current_line: int) -> Tuple[int, int]:
        """Default boundary detection for unknown languages."""
        # Simple heuristic: look for blank lines or significant indentation changes
        start_line = current_line
        end_line = current_line

        # Search backward
        for i in range(current_line - 1, -1, -1):
            if not lines[i].strip() and i < current_line - 1:
                start_line = i + 2
                break
        else:
            start_line = 1

        # Search forward
        for i in range(current_line, len(lines)):
            if not lines[i].strip() and i > current_line:
                end_line = i
                break
        else:
            end_line = len(lines)

        return (start_line, end_line)

    def get_function_boundaries(
        self, source_file: str, address: int, current_line: int, lines: List[str]
    ) -> Tuple[int, int, Optional[str]]:
        """
        Main entry point to get function boundaries.
        Returns (start_line, end_line, function_name) where lines are 1-based.
        """
        # First try GDB debug info
        gdb_result = self.get_function_boundaries_from_gdb(address)
        if gdb_result:
            return gdb_result

        # Fall back to heuristics
        language = self.detect_language(source_file)
        start_line, end_line = self.find_function_boundaries_heuristic(
            lines, current_line, language
        )

        # Try to extract function name from the start line
        func_name = None
        if start_line > 0 and start_line <= len(lines):
            func_name = self._extract_function_name(lines[start_line - 1], language)

        return (start_line, end_line, func_name)

    def _extract_function_name(self, line: str, language: Language) -> Optional[str]:
        """Extract function name from a line based on language patterns."""
        if language not in self.patterns:
            return None

        patterns = self.patterns[language]["start"]
        for pattern in patterns:
            match = re.match(pattern, line)
            if match and match.groups():
                return match.group(1)

        return None


# Integration function for pwndbg
def get_function_boundaries_for_src(
    source_file: str, address: int, current_line: int, lines: List[str]
) -> Tuple[int, int]:
    """
    Get function boundaries for the src command.
    Returns (start_line, end_line) as 1-based indices.
    """
    detector = FunctionBoundaryDetector()
    start, end, func_name = detector.get_function_boundaries(
        source_file, address, current_line, lines
    )

    # Ensure boundaries are within valid range
    start = max(1, start)
    end = min(len(lines), end)

    # If we found a function name, we could display it
    if func_name:
        print(f"Function: {func_name}")

    return (start, end)
