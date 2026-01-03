from __future__ import annotations

import re
from typing import Any
from typing import Callable
from typing import Optional
from typing import Tuple

from pwnlib.constants.constant import Constant
from pwnlib.constants.linux import aarch64 as linux_aarch64
from pwnlib.constants.linux import amd64 as linux_amd64
from pwnlib.constants.linux import arm as linux_arm
from pwnlib.constants.linux import i386 as linux_i386
from pwnlib.constants.linux import mips as linux_mips
from pwnlib.constants.linux import powerpc as linux_powerpc
from pwnlib.constants.linux import powerpc64 as linux_powerpc64
from pwnlib.constants.linux import riscv64 as linux_riscv64
from pwnlib.constants.linux import s390x as linux_s390x
from pwnlib.constants.linux import sparc as linux_sparc
from pwnlib.constants.linux import sparc64 as linux_sparc64
from pwnlib.constants.linux import thumb as linux_thumb

import pwndbg.aglib
from pwndbg.lib.regs import reg_sets


def get_arch_module() -> Any:
    """
    Gets the architecture module for the current architecture.

    Returns None if no architecture is set (e.g., no process running).
    """
    # pwndbg.aglib.arch is None before a process starts
    if pwndbg.aglib.arch is None:
        return None

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
        "sparc64": linux_sparc64,
        "powerpc": linux_powerpc,
        "powerpc64": linux_powerpc64,
        "s390x": linux_s390x,
        # Note: loongarch64 not available in pwnlib
    }.get(pwndbg.aglib.arch.name)

    return arch_module


def get_syscall(name_or_num: str) -> Tuple[Optional[int], Optional[str]]:
    """
    Resolve the syscall into (number, name).

    Accepts:
        - Syscall number as string: "1", "60", "0x3c"
        - Syscall name with SYS_ prefix: "SYS_write", "SYS_exit"

    Returns (None, None) if the syscall is not found or input is invalid.
    """
    if name_or_num is None or not isinstance(name_or_num, str):
        return (None, None)

    # Handle empty string
    if not name_or_num.strip():
        return (None, None)

    arch_module = get_arch_module()
    if arch_module is None:
        return (None, None)

    try:
        num = int(name_or_num, 0)  # base 0 auto-detects: 0x for hex, 0o for octal
        SYS_BY_NUM = {
            int(value): value
            for attr_name, value in vars(arch_module).items()
            if attr_name.startswith("__NR_") and isinstance(value, Constant)
        }
        name = SYS_BY_NUM.get(num)
        if name is None:
            return (None, None)
        return (num, name)
    except ValueError:
        pass  # Not a number, try as name

    # Handle name lookup
    if name_or_num.startswith("SYS_"):
        syscall_name = name_or_num[4:]  # "SYS_write" -> "write"
    else:
        return (None, None)

    SYS_BY_NAME = {
        attr_name[5:]: value  # "__NR_write" -> "write"
        for attr_name, value in vars(arch_module).items()
        if attr_name.startswith("__NR_") and isinstance(value, Constant)
    }

    num = SYS_BY_NAME.get(syscall_name)
    if num is None:
        return (None, None)
    return (int(num), name_or_num)


def parse_condition(condition: str) -> Optional[Callable[[], bool]]:
    """
    Parses a condition string into a callable that returns a boolean.

    Returns None if the condition cannot be parsed.
    """
    pattern = r"^\$?(\w+)\s*(==|!=|>=|<=|>|<)\s*(.+)$"
    match = re.match(pattern, condition.strip())
    if not match:
        return None

    reg_name, operator, value = match.groups()

    if pwndbg.aglib.arch is not None:
        register_set = reg_sets.get(pwndbg.aglib.arch.name)
        if register_set and reg_name not in register_set.all:
            return None

    ops: dict[str, Callable[[int, int], bool]] = {
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
    }

    op_func = ops[operator]

    def evaluator() -> bool:
        try:
            reg_val = pwndbg.aglib.regs.read_reg(reg_name)
            if reg_val is None:
                return False

            # Parse comparison value
            cmp_val = int(value.strip(), 0)
            return op_func(reg_val, cmp_val)

        except (ValueError, KeyError):
            return False

    return evaluator
