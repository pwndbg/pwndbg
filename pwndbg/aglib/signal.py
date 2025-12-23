"""
Generating detailed information about signals received by the debugged process.
"""

from __future__ import annotations
from enum import Enum
from typing import Optional, Tuple, Dict, Callable
import pwndbg
import pwndbg.lib.arch

if pwndbg.dbg.is_gdblib_available():
    import gdb

def get_segv_pkuerr_description() -> Optional[str]:
    """Retrieve the long description for SEGV_PKUERR, if applicable."""
    fault_addr = int(gdb.parse_and_eval("$_siginfo._sifields._sigfault.si_addr"))
    fault_mem_page = pwndbg.aglib.vmmap.find(fault_addr)
    if fault_mem_page.protection_key is None:
        return None
    msg = f'Violated protection key {fault_mem_page.protection_key}'
    pkru = pwndbg.aglib.regs.read_reg('pkru')
    if pkru is None:
        return msg
    ad = 1 if pkru & (1 << (fault_mem_page.protection_key * 2)) else 0
    wd = 1 if pkru & (1 << (fault_mem_page.protection_key * 2 + 1)) else 0
    msg += f'(AD={ad}, WD={wd})'
    return msg

class SegvCodeX86_64(Enum):
    SEGV_PKUERR = 4  # Protection key violation (PKU)

SHORT_SEGV_DESCRIPTIONS_X86_64: Dict[SegvCodeX86_64, str] = {
    SegvCodeX86_64.SEGV_PKUERR: "SEGV_PKUERR"
}

LONG_SEGV_DESCRIPTIONS_X86_64: Dict[SegvCodeX86_64, Callable[[], str]] = {
    SegvCodeX86_64.SEGV_PKUERR: get_segv_pkuerr_description
}

PER_ARCH_SEGV_CODES: Dict[pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Enum] = {
    "x86-64": SegvCodeX86_64,
}

SHORT_SEGV_DESCRIPTIONS: Dict[pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Dict[Enum, str]] = {
    "x86-64": SHORT_SEGV_DESCRIPTIONS_X86_64,
}

LONG_SEGV_DESCRIPTIONS: Dict[pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, Dict[Enum, str]] = {
    "x86-64": LONG_SEGV_DESCRIPTIONS_X86_64,
}

def get_segv_information() -> Tuple[str, Optional[str]]:
    """Retrieve additional information about a SIGSEGV signal, if available."""
    try:
        si_code = int(gdb.parse_and_eval("$_siginfo.si_code"))
        curr_arch = pwndbg.aglib.arch.name
        segv_code_enum = PER_ARCH_SEGV_CODES.get(curr_arch)
        if segv_code_enum is None:
            return 'SIGSEGV', None
        
        if not any(si_code == e.value for e in segv_code_enum):
            return 'SIGSEGV', None
        
        segv_code = segv_code_enum(si_code)
        desc_short = SHORT_SEGV_DESCRIPTIONS.get(curr_arch, {}).get(segv_code, 'SIGSEGV')
        desc_long_fn = LONG_SEGV_DESCRIPTIONS.get(curr_arch, {}).get(segv_code)
        desc_long = desc_long_fn() if desc_long_fn else None

        return desc_short, desc_long

    except gdb.error:
        return 'SIGSEGV', None
