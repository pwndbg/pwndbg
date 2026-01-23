from __future__ import annotations

from pathlib import Path

import pwndbg.aglib.symbol


def version_parse(data: bytearray) -> tuple[int, ...]:
    """
    Parse the version bytestring as read from memory into
    an integer tuple.
    """
    # Example from compiled musl: 1.2.5-git-103-g7bcf8783
    data = data.split(b"-")[0]
    return tuple(int(part) for part in data.split(b"."))


def has_exported_symbols(mapping_name: str) -> bool:
    # fscanf must be implemented by a libc.
    return pwndbg.aglib.symbol.lookup_symbol("fscanf", objfile_endswith=mapping_name) is not None


def clean_path(path: str) -> str:
    # Why try to avoid: Path("[heap]").resolve() == PosixPath('/home/user/<cwd>/[heap]')
    # FIXME: This is quite flaky and should be standardized in the codebase, see #3641 .
    if not (path.startswith("target:") or path.startswith("[")):
        return str(Path(path).resolve())
    return str(Path(path))
