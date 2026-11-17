from __future__ import annotations

from pwndbg.lib.syscall import syscall_name_to_number
from pwndbg.lib.syscall import syscall_number_to_name


def test_loongarch64_syscall_names() -> None:
    assert syscall_number_to_name(64, "loongarch64") == "write"
    # Only in the loongarch64 table, not in riscv64's
    assert syscall_number_to_name(455, "loongarch64") == "futex_wait"
    # riscv64-only syscall
    assert syscall_number_to_name(259, "loongarch64") is None

    assert syscall_name_to_number("SYS_futex_wait", "loongarch64") == 455
    assert syscall_name_to_number("riscv_flush_icache", "loongarch64") is None
