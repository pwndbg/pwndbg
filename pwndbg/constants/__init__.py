from __future__ import annotations

from types import ModuleType
from typing import Dict

from . import aarch64
from . import amd64
from . import arm
from . import i386
from . import mips
from . import riscv64
from . import thumb

arches: Dict[str, ModuleType] = {
    "arm": arm,
    "armcm": arm,
    "i386": i386,
    "mips": mips,
    "x86-64": amd64,
    "aarch64": aarch64,
    "rv32": riscv64,
    "rv64": riscv64,
}


def syscall(number: int, arch: str) -> str | None:
    """
    Given a syscall number and architecture, returns the name of the syscall.
    E.g. execve == 59 on x86-64
    """
    arch_module = arches.get(arch)

    if arch_module is None:
        return None

    prefix = "__NR_"

    for k, v in arch_module.__dict__.items():
        if v != number:
            continue

        if not k.startswith(prefix):
            continue

        return k[len(prefix) :].lower()

    return None
