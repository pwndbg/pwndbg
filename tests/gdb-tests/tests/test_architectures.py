from __future__ import annotations

from pwndbg.aglib.arch import registered_architectures
from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES


def test_all_pwndbg_architectures_are_defined():
    for arch in PWNDBG_SUPPORTED_ARCHITECTURES:
        assert arch in registered_architectures
