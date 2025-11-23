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

import pwndbg.aglib.symbol
import pwndbg.dbg


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
    """Detects function boundaries using debug info and language heuristics."""

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
                    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    r"^(?:static|inline|extern)\s+[\w\s\*]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    r"^[\w\s\*]+\s+(__attribute__\s*\([^)]+\)\s*)?([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                ],
                "end": r"^}",
                "continuation": r"^\s*{",
            },
            Language.CPP: {
                "start": [
                    r"^(?:[\w\s]*::)?([a-zA-Z_]\w*)\s*\([^)]*\)(?:\s*const)?\s*(?:override|final)?\s*{",
                    r"^template\s*<[^>]*>\s*[\w\s\*]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                    r"^([a-zA-Z_]\w*)::\1\s*\([^)]*\)\s*(?::[^{]+)?\s*{",
                    r"^([a-zA-Z_]\w*)::~\1\s*\([^)]*\)\s*{",
                    r"^[a-zA-Z_][\w\s\*]*\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*{",
                ],
                "end": r"^}",
                "continuation": r"^\s*{",
            },
            Language.RUST: {
                "start": [
                    r'^\s*(?:pub(?:\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+(?:"[^"]+"\s+)?)?fn\s+([a-zA-Z_]\w*)',
                    r"^\s*(?:pub(?:\([^)]+\))?\s+)?fn\s+([a-zA-Z_]\w*)\s*\(",
                    r"^\s*let\s+([a-zA-Z_]\w*)\s*=\s*\|[^|]*\|\s*{",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.GO: {
                "start": [
                    r"^func\s+([a-zA-Z_]\w*)\s*\(",
                    r"^func\s+\([^)]+\)\s+([a-zA-Z_]\w*)\s*\(",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.PYTHON: {
                "start": [
                    r"^(?:async\s+)?def\s+([a-zA-Z_]\w*)\s*\(",
                    r"^class\s+([a-zA-Z_]\w*)",
                ],
                "end": None,
                "indent_based": True,
            },
            Language.JAVA: {
                "start": [
                    r"^\s*(?:(?:public|private|protected|static|final|abstract|synchronized|native)\s+)*[\w<>\[\]]+\s+([a-zA-Z_]\w*)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*{",
                    r"^\s*(?:public|private|protected)\s+([A-Z]\w*)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*{",
                ],
                "end": r"^}",
                "continuation": r"{\s*$",
            },
            Language.JAVASCRIPT: {
                "start": [
                    r"^(?:async\s+)?function\s+([a-zA-Z_$][\w$]*)\s*\(",
                    r"^\s*(?:async\s+)?([a-zA-Z_$][\w$]*)\s*\([^)]*\)\s*{",
                    r"^\s*(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>",
                ],
                "end": r"^}",
                "continuation": r"{\s*$|=>\s*{\s*$",
            },
            Language.ASSEMBLY: {
                "start": [
                    r"^([a-zA-Z_]\w*):\s*$",
                    r"^\s*\.glob[a]?l\s+([a-zA-Z_]\w*)",
                ],
                "end": [
                    r"^\s*ret\s*$",
                    r"^\s*retn\s*$",
                    r"^\s*jmp\s+",
                    r"^([a-zA-Z_]\w*):\s*$",
                ],
                "special": True,
            },
        }

    def detect_language(self, filename: str) -> Language:
        """Detect language from filename extension."""
        ext = os.path.splitext(filename)[1].lower()
        return self.extension_map.get(ext, Language.UNKNOWN)

    def get_function_boundaries_from_debug_info(
        self, address: int, lines: List[str]
    ) -> Optional[Tuple[int, int, str]]:
        """
        Return (start_line, end_line, symbol_name) via debug info.
        start_line / end_line can be None when we cannot map the address to line,
        but we still return the function name so callers may fall back to it.
        """
        if pwndbg.dbg.is_gdblib_available():
            try:
                import gdb

                blk = gdb.block_for_pc(address)
                if blk is None:
                    return None

                while blk and not blk.function:
                    blk = blk.superblock
                if blk is None or blk.start is None or blk.end is None:
                    return None

                start_sal = gdb.find_pc_line(int(blk.start))
                end_sal = gdb.find_pc_line(int(blk.end) - 1)

                if start_sal.symtab is None or end_sal.symtab is None:
                    return None

                return (start_sal.line, end_sal.line, blk.function.print_name)

            except Exception:
                return None
        else:
            # For LLDB, we can't get exact boundaries yet
            # Just try to get the symbol name
            try:
                symbol = pwndbg.aglib.symbol.resolve_addr(address)
                if symbol:
                    func_name = symbol.split("+")[0] if "+" in symbol else symbol
                    return (None, None, func_name)
            except Exception:
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
            return self._default_boundaries(lines, current_line)

        pattern_info = self.patterns[language]

        if pattern_info.get("indent_based"):
            return self._find_python_boundaries(lines, current_line)

        if pattern_info.get("special") and language == Language.ASSEMBLY:
            return self._find_assembly_boundaries(lines, current_line)

        return self._find_brace_boundaries(lines, current_line, pattern_info)

    def _find_brace_boundaries(
        self,
        lines: List[str],
        current_line: int,
        pattern_info: Dict[str, Any],
    ) -> Tuple[int, int]:
        """Find boundaries for brace-based languages (C, C++, Java, etc.)."""
        start_patterns = pattern_info["start"]
        current_idx = current_line - 1
        start_idx = current_idx
        found_start = False

        for i in range(current_idx, -1, -1):
            line = lines[i]

            for pattern in start_patterns:
                if re.match(pattern, line):
                    if "{" in line:
                        start_idx = i
                        found_start = True
                        break
                    for j in range(i, min(i + 3, len(lines))):
                        if "{" in lines[j]:
                            start_idx = i
                            found_start = True
                            break
                    if found_start:
                        break
            if found_start:
                break

        if not found_start:
            for i in range(current_idx, -1, -1):
                line = lines[i]
                if "{" in line and "(" in line and ")" in line:
                    start_idx = i
                    break
                if i > 0 and "{" in line:
                    prev_line = lines[i - 1]
                    if "(" in prev_line and ")" in prev_line:
                        start_idx = i - 1
                        break

        brace_count = 0
        end_idx = start_idx
        found_opening = False

        for i in range(start_idx, len(lines)):
            line = lines[i]

            if "//" in line:
                line = line[: line.index("//")]

            for char in line:
                if char == "{":
                    brace_count += 1
                    found_opening = True
                elif char == "}":
                    brace_count -= 1

                    if found_opening and brace_count == 0:
                        end_idx = i
                        return (start_idx + 1, end_idx + 1)

        if end_idx == start_idx:
            for i in range(current_idx + 1, len(lines)):
                line = lines[i]
                for pattern in start_patterns:
                    if re.match(pattern, line):
                        end_idx = i - 1
                        return (start_idx + 1, end_idx + 1)
            end_idx = min(start_idx + 50, len(lines) - 1)

        return (start_idx + 1, end_idx + 1)

    def _find_python_boundaries(
        self, lines: List[str], current_line: int
    ) -> Tuple[int, int]:
        """Find boundaries for Python functions using indentation."""
        if not lines:
            return (1, 1)

        current_indent = len(lines[current_line - 1]) - len(
            lines[current_line - 1].lstrip()
        )

        start_line = current_line
        for i in range(current_line - 1, -1, -1):
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            if re.match(r"^(?:async\s+)?def\s+\w+|^class\s+\w+", line):
                start_line = i + 1
                break

            line_indent = len(line) - len(line.lstrip())
            if line_indent < current_indent and stripped:
                break

        end_line = current_line
        base_indent = len(lines[start_line - 1]) - len(lines[start_line - 1].lstrip())

        for i in range(current_line, len(lines)):
            line = lines[i]
            stripped = line.strip()

            if not stripped:
                continue

            line_indent = len(line) - len(line.lstrip())
            if line_indent <= base_indent and i > start_line:
                end_line = i
                break
        else:
            end_line = len(lines)

        return (start_line, end_line)

    def _find_assembly_boundaries(
        self, lines: List[str], current_line: int
    ) -> Tuple[int, int]:
        """Find boundaries for assembly functions."""
        start_line = current_line
        for i in range(current_line - 1, -1, -1):
            line = lines[i].strip()
            if re.match(r"^[a-zA-Z_]\w*:\s*$", line) or re.match(
                r"^\s*\.glob[a]?l\s+", line
            ):
                start_line = i + 1
                break

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

    def _default_boundaries(
        self, lines: List[str], current_line: int
    ) -> Tuple[int, int]:
        """Default boundary detection for unknown languages."""
        start_line = current_line
        end_line = current_line

        for i in range(current_line - 1, -1, -1):
            if not lines[i].strip() and i < current_line - 1:
                start_line = i + 2
                break
        else:
            start_line = 1

        for i in range(current_line, len(lines)):
            if not lines[i].strip() and i > current_line:
                end_line = i
                break
        else:
            end_line = len(lines)

        return (start_line, end_line)

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

    def get_function_boundaries(
        self,
        source_file: str,
        address: int,
        current_line: int,
        lines: List[str],
    ) -> Tuple[int, int, Optional[str]]:
        """
        Returns (start_line, end_line, function_name); lines are 1-based.
        """
        dbg = self.get_function_boundaries_from_debug_info(address, lines)
        if dbg:
            start_line, end_line, name = dbg

            if start_line is not None and end_line is not None:
                # Validate debug info: if it reports a single-line function,
                # check if it's actually a one-liner (has closing brace) or
                # if debug info is incomplete (e.g., Go debug info issues)
                if end_line == start_line:
                    # Check if this line contains a closing brace
                    # If not, debug info is likely incomplete
                    if start_line <= len(lines):
                        line_content = lines[start_line - 1]
                        if "}" not in line_content:
                            # Debug info incomplete, use heuristic
                            language = self.detect_language(source_file)
                            h_start, h_end = self.find_function_boundaries_heuristic(
                                lines, current_line, language
                            )
                            return h_start, h_end, name

                # Adjust start_line to include function declaration if needed
                s = start_line
                while s > 1:
                    prev = lines[s - 2]
                    if "{" in prev or not prev.strip():
                        break
                    s -= 1
                start_line = s
                return start_line, end_line, name

            if name:
                language = self.detect_language(source_file)
                h_start, h_end = self.find_function_boundaries_heuristic(
                    lines, current_line, language
                )
                return h_start, h_end, name

        language = self.detect_language(source_file)
        start_line, end_line = self.find_function_boundaries_heuristic(
            lines, current_line, language
        )
        func_name = (
            self._extract_function_name(lines[start_line - 1], language)
            if start_line > 0
            else None
        )
        return start_line, end_line, func_name


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

    start = max(1, start)
    end = min(len(lines), end)

    if func_name:
        print(f"Function: {func_name}")

    return (start, end)
