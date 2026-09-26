#!/usr/bin/env python
"""
Check for custom Pwndbg lint rules on the codebase.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PWNDBG_ROOT: Path = Path(__file__).parent.parent
pwndbg_lib_py_files: list[Path] = list((PWNDBG_ROOT / "pwndbg/lib/").rglob("*.py"))
pwndbg_libc_no_init_py_files: list[Path] = [
    # Ideally I would like to catch only pwndbg/libc/__init__.py, but okay should be good
    # enough.
    f
    for f in (PWNDBG_ROOT / "pwndbg/libc/").rglob("*.py")
    if f.name != "__init__.py"
]


RED = "\x1b[31m"
NORMAL = "\x1b[0m"

LINT_FAILED: bool = False


def red(x: str) -> str:
    return RED + x.replace(NORMAL, NORMAL + RED) + NORMAL


def check_forbiden_in_lines(
    files: list[Path], forbidden: list[str], err_msg: str, exceptions: dict[Path, list[str]]
) -> None:
    """
    Check if any of the files specified in `files` match any of the regex's
    specified in `forbidden`. If so, print the offending line, the `err_msg`,
    and set LINT_FAILED=True.

    `exceptions` is a dictionary from file to a list of lines which are hardcoded
    to be fine. The line *content* is specified, and matched for exactly.
    """
    global LINT_FAILED

    for file in files:
        lines = file.read_text().splitlines()
        line_idx = 0
        for line in lines:
            line_idx += 1
            if line in exceptions.get(file, []):
                print(f"skipping {file}:{line_idx}..")
                continue

            for bad in forbidden:
                if re.search(bad, line) is not None:
                    # Lint failed.
                    print("\n[!] Rule violation [!]")
                    print(f"Rule: {err_msg}")
                    print(f"But matched regex `{bad}` in {file}:{line_idx} :")
                    print(f"=============\n{line}\n=============\n")
                    LINT_FAILED = True


def lib_is_pure() -> None:
    """
    Checks that pwndbg/lib/ does not contain any references
    to pwndbg.aglib, pwndbg.dbg and pwndbg.dbg_mod .
    """
    forbidden: list[str] = [
        "pwndbg\\.aglib",
        "pwndbg\\.dbg",
        "pwndbg\\.dbg_mod",
        "from pwndbg import aglib",
        # import pwndbg.anything is bad, except import pwndbg.lib and pwndbg.color
        r"import\s+pwndbg\.(?!lib)(?!color)",
    ]
    exceptions: dict[Path, list[str]] = {
        (PWNDBG_ROOT / "pwndbg/lib/tips.py"): [
            # It's just a tip, not actual code, so it's fine.
            '    "Use GDB\'s `pi` command to run an interactive Python console where you can use Pwndbg APIs like `pwndbg.aglib.memory.read(addr, len)`, `pwndbg.aglib.memory.write(addr, data)`, `pwndbg.aglib.vmmap.get()` and so on!",',
            # It's a comment.
            "    You should pass in pwndbg.dbg.name().value .",
        ],
        (PWNDBG_ROOT / "pwndbg/lib/cache.py"): [
            # It's a comment.
            "    Not necessarily 1:1 with pwndbg.dbg_mod.EventTypes , but"
        ],
    }

    check_forbiden_in_lines(
        pwndbg_lib_py_files,
        forbidden,
        "[lib_is_pure] You may not reference debugger-related logic in pwndbg/lib/ files!\n"
        "See: https://pwndbg.re/dev/contributing/common-pitfalls/#pwndbglib-files-should-only-access-pwndbglib .",
        exceptions,
    )


def libc_no_facade() -> None:
    """
    Checks that none of the files in pwndbg/libc/ access facade.py except for __init__.py.
    """
    forbidden: list[str] = ["facade"]
    exceptions: dict[Path, list[str]] = {
        # In docstring.
        (PWNDBG_ROOT / "pwndbg/libc/dispatch.py"): [
            "    Libc implementations must conform to this protocol in order to be properly used by the facade."
        ]
    }
    check_forbiden_in_lines(
        pwndbg_libc_no_init_py_files,
        forbidden,
        "[libc_no_facade] facade.py is the frontend of the pwndbg/libc/ API. It can access everything\n"
        "else, and so noone else (except __init__.py) should acccess it.",
        exceptions,
    )


def main() -> None:
    lib_is_pure()
    libc_no_facade()

    if LINT_FAILED:
        print(red("Fatal: Custom lint check failed. See the violations above^."))
        print(
            "If you think the check is erroneous (e.g. we matched on a comment), feel free to fix"
        )
        print("it or add an exception (scripts/custom-lint.py).")
        sys.exit(1)
    else:
        print("Passed!")


if __name__ == "__main__":
    main()
