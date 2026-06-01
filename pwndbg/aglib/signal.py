"""
Generating detailed information about signals received by the debugged process.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import Any
from typing import Literal

import pwndbg
import pwndbg.aglib.vmmap
import pwndbg.dbg_mod
import pwndbg.lib.arch


def get_segv_pkuerr_description() -> str | None:
    """Retrieve the long description for SEGV_PKUERR, if applicable."""
    curr_thread = pwndbg.dbg.selected_thread()
    if curr_thread is None:
        return None
    siginfo = curr_thread.siginfo()
    if siginfo is None:
        return None
    fault_mem_page = pwndbg.aglib.vmmap.find(siginfo.sigfault.si_addr)
    if fault_mem_page is None or fault_mem_page.protection_key is None:
        return None
    msg = f" Violated protection key {fault_mem_page.protection_key}"
    pkru = pwndbg.aglib.regs.read_reg("pkru")
    if pkru is None:
        return msg
    ad = 1 if pkru & (1 << (fault_mem_page.protection_key * 2)) else 0
    wd = 1 if pkru & (1 << (fault_mem_page.protection_key * 2 + 1)) else 0
    msg += f"(AD={ad}, WD={wd})"
    return msg


SIGNALS = Literal[
    "SIGABRT",
    "SIGALRM",
    "SIGBUS",
    "SIGCHLD",
    "SIGCLD",
    "SIGCONT",
    "SIGEMT",
    "SIGFPE",
    "SIGHUP",
    "SIGILL",
    "SIGINFO",
    "SIGINT",
    "SIGIO",
    "SIGIOT",
    "SIGKILL",
    "SIGLOST",
    "SIGPIPE",
    "SIGPOLL",
    "SIGPROF",
    "SIGPWR",
    "SIGQUIT",
    "SIGSEGV",
    "SIGSTKFLT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGSYS",
    "SIGTERM",
    "SIGTRAP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGUNUSED",
    "SIGURG",
    "SIGUSR1",
    "SIGUSR2",
    "SIGVTALRM",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGWINCH",
]

SHARED_NUM_TO_SIGNAL_MAPPING: dict[int, SIGNALS] = {
    1: "SIGHUP",
    2: "SIGINT",
    3: "SIGQUIT",
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    8: "SIGFPE",
    9: "SIGKILL",
    11: "SIGSEGV",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
}

COMMON_NUM_TO_SIGNAL_MAPPING: dict[int, SIGNALS] = {
    **SHARED_NUM_TO_SIGNAL_MAPPING,
    7: "SIGBUS",
    10: "SIGUSR1",
    12: "SIGUSR2",
    16: "SIGSTKFLT",
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGURG",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGIO",
    30: "SIGPWR",
    31: "SIGSYS",
}

# https://man7.org/linux/man-pages/man7/signal.7.html
PER_ARCH_SIGNAL_MAPPINGS: dict[
    pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, dict[int, SIGNALS]
] = {
    "x86-64": COMMON_NUM_TO_SIGNAL_MAPPING,
    "aarch64": COMMON_NUM_TO_SIGNAL_MAPPING,
}


class SegvCodeX86_64(Enum):
    SEGV_PKUERR = 4  # Protection key violation (PKU)


SHORT_SEGV_DESCRIPTIONS_X86_64: dict[SegvCodeX86_64, str] = {
    SegvCodeX86_64.SEGV_PKUERR: "SEGV_PKUERR"
}

LONG_SEGV_DESCRIPTIONS_X86_64: dict[SegvCodeX86_64, Callable[[], str | None]] = {
    SegvCodeX86_64.SEGV_PKUERR: get_segv_pkuerr_description
}

PER_ARCH_SEGV_CODES: dict[pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, type[Enum]] = {
    "x86-64": SegvCodeX86_64,
}

SHORT_SEGV_DESCRIPTIONS: dict[
    pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE, dict[Any, str]
] = {
    "x86-64": SHORT_SEGV_DESCRIPTIONS_X86_64,
}

LONG_SEGV_DESCRIPTIONS: dict[
    pwndbg.lib.arch.PWNDBG_SUPPORTED_ARCHITECTURES_TYPE,
    dict[Any, Callable[[], str | None]],
] = {
    "x86-64": LONG_SEGV_DESCRIPTIONS_X86_64,
}


def get_segv_information() -> tuple[str, str | None]:
    """Retrieve additional information about a SIGSEGV signal, if available."""
    try:
        curr_thread = pwndbg.dbg.selected_thread()
        if curr_thread is None:
            return "SIGSEGV", None
        siginfo = curr_thread.siginfo()
        if siginfo is None:
            return "SIGSEGV", None
        si_code = siginfo.si_code
        desc_short = "SIGSEGV"
        desc_long = f" (fault address: {siginfo.sigfault.si_addr:#x})."
        curr_arch = pwndbg.aglib.arch.name
        segv_code_enum = PER_ARCH_SEGV_CODES.get(curr_arch)
        if segv_code_enum is None:
            return desc_short, desc_long

        if not any(si_code == e.value for e in segv_code_enum):
            return desc_short, desc_long

        segv_code = segv_code_enum(si_code)
        segv_type = SHORT_SEGV_DESCRIPTIONS.get(curr_arch, {}).get(segv_code, "SIGSEGV")
        if segv_type is not None:
            desc_short = segv_type
        desc_long_fn = LONG_SEGV_DESCRIPTIONS.get(curr_arch, {}).get(segv_code)
        desc_long_fn_val = desc_long_fn() if desc_long_fn else None
        if desc_long_fn_val is not None:
            desc_long += desc_long_fn_val

        return desc_short, desc_long

    except pwndbg.dbg_mod.Error:
        return "SIGSEGV", None


def get_last_signal() -> SIGNALS | None:
    """Get the last signal received by the debugged process."""
    curr_thread = pwndbg.dbg.selected_thread()
    if curr_thread is None:
        return None
    siginfo = curr_thread.siginfo()
    if siginfo is None:
        return None
    curr_arch = pwndbg.aglib.arch.name
    sig_mapping = PER_ARCH_SIGNAL_MAPPINGS.get(curr_arch, SHARED_NUM_TO_SIGNAL_MAPPING)
    return sig_mapping.get(siginfo.si_signo)
