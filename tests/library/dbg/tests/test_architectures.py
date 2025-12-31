from __future__ import annotations


def test_all_pwndbg_architectures_are_defined():
    from pwndbg.aglib.arch_mod import registered_architectures
    from pwndbg.lib.arch import PWNDBG_SUPPORTED_ARCHITECTURES

    for arch in PWNDBG_SUPPORTED_ARCHITECTURES:
        assert arch in registered_architectures
