from __future__ import annotations  

from pwnlib.constants import linux
import pwndbg.aglib
from typing import Optional,Tuple
from pwnlib.constants.constant import Constant

def get_arch_module():
    """
    Gets the architecture module for the current architecture.
    
    Returns None if no architecture is set (e.g., no process running).
    """
    # pwndbg.aglib.arch is None before a process starts
    if pwndbg.aglib.arch is None:
        return None
    
    arch_module = { 
        "x86-64": linux.amd64,
        "i386": linux.i386,
        "i8086": linux,
        "mips": linux.mips,
        "aarch64": linux.aarch64,
        "arm": linux.arm,
        "armcm": linux.thumb,
        "rv32": linux.riscv64,
        "rv64": linux.riscv64,
        "sparc": linux.sparc,
        "powerpc": linux.powerpc,
        "loongarch64": linux.loongarch64,
        "s390x": linux.s390x,
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

