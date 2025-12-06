from __future__ import annotations

import os
import platform

BINARIES_PATH = os.environ.get("TEST_BINARIES_ROOT")


def get_binary(name: str) -> str:
    return os.path.join(BINARIES_PATH, name)


def get_host_glibc_version():
    impl, version = platform.libc_ver()

    if impl.lower() != "glibc":
        return (0, 0)

    try:
        return tuple(map(int, version.split(".")[:2]))
    except (ValueError, AttributeError):
        return (0, 0)
