from __future__ import annotations

from pathlib import Path


def clean_path(path: str) -> str:
    # Why try to avoid: Path("[heap]").resolve() == PosixPath('/home/user/<cwd>/[heap]')
    # FIXME: This is quite flaky and should be standardized in the codebase, see #3641 .
    if not (path.startswith(("target:", "["))):
        return str(Path(path).resolve())
    return str(Path(path))
