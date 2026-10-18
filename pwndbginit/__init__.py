from __future__ import annotations

RELOADING = False


def is_reloading() -> bool:
    return RELOADING


def set_reloading_status(status: bool) -> None:
    global RELOADING
    RELOADING = status
