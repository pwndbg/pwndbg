from __future__ import annotations

from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES
from pwndbg.lib.regs import reg_sets


def test_reg_set_mappings_exist():
    arch_set: set[str] = set(PWNDBG_SUPPORTED_ARCHITECTURES)
    reg_sets_keys = set(reg_sets.keys())

    assert arch_set == reg_sets_keys
