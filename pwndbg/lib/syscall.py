from __future__ import annotations

from typing import Any

from pwnlib.constants.constant import Constant
from pwnlib.constants.linux import aarch64 as linux_aarch64
from pwnlib.constants.linux import amd64 as linux_amd64
from pwnlib.constants.linux import arm as linux_arm
from pwnlib.constants.linux import i386 as linux_i386
from pwnlib.constants.linux import mips as linux_mips
from pwnlib.constants.linux import powerpc as linux_powerpc
from pwnlib.constants.linux import riscv64 as linux_riscv64
from pwnlib.constants.linux import s390x as linux_s390x
from pwnlib.constants.linux import sparc as linux_sparc
from pwnlib.constants.linux import thumb as linux_thumb

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES_TYPE


def _get_pwntools_arch_module(arch_name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> Any:
    """
    Gets the pwntools architecture module for the given architecture.

    Returns None if the architecture is unsupported.
    """
    arch_module = {
        "x86-64": linux_amd64,
        "i386": linux_i386,
        "i8086": linux_i386,
        "mips": linux_mips,
        "aarch64": linux_aarch64,
        "arm": linux_arm,
        "armcm": linux_thumb,
        "rv32": linux_riscv64,
        "rv64": linux_riscv64,
        "sparc": linux_sparc,
        "powerpc": linux_powerpc,
        "s390x": linux_s390x,
        # Note: loongarch64 and sparc64 not available in pwnlib
    }.get(arch_name)

    return arch_module


def syscall_number_to_name(num: int, arch_name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> str | None:
    """
    Given a syscall number, return the syscall name (e.g., "write", "exit").

    Returns None if the syscall number is not found or architecture is unsupported.
    """
    arch_module = _get_pwntools_arch_module(arch_name)
    if arch_module is None:
        return None

    for attr_name, value in vars(arch_module).items():
        if attr_name.startswith("__NR_") and isinstance(value, Constant) and int(value) == num:
            return str(attr_name[5:])  # "__NR_write" -> "write"

    return None


def syscall_name_to_number(name: str, arch_name: PWNDBG_SUPPORTED_ARCHITECTURES_TYPE) -> int | None:
    """
    Given a syscall name (e.g., "write" or "SYS_write"), return the syscall number.

    Returns None if the syscall name is not found or architecture is unsupported.
    """
    arch_module = _get_pwntools_arch_module(arch_name)
    if arch_module is None:
        return None

    # Strip SYS_ prefix if present
    name = name.removeprefix("SYS_")

    attr_name = f"__NR_{name}"
    value = getattr(arch_module, attr_name, None)
    if value is not None and isinstance(value, Constant):
        return int(value)

    return None
