from __future__ import annotations

import os

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT")


def get_binary(name: str) -> str:
    return os.path.join(BINARIES_PATH, name)
