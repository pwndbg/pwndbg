from __future__ import annotations

from pwndbg.lib.abi import DEFAULT_ABIS
from pwndbg.lib.abi import SIGRETURN_ABIS
from pwndbg.lib.abi import SYSCALL_ABIS


def test_loongarch64_abi_registered() -> None:
    assert DEFAULT_ABIS[(64, "loongarch64", "linux")] is not None
    assert SYSCALL_ABIS[(64, "loongarch64", "linux")] is not None
    assert SIGRETURN_ABIS[(64, "loongarch64", "linux")] is not None


def test_s390x_abi_registered() -> None:
    assert DEFAULT_ABIS[(64, "s390x", "linux")] is not None
    assert SYSCALL_ABIS[(64, "s390x", "linux")] is not None
    assert SIGRETURN_ABIS[(64, "s390x", "linux")] is not None


def test_existing_architectures_unaffected() -> None:
    assert DEFAULT_ABIS[(64, "aarch64", "linux")] is not None
