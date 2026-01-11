from __future__ import annotations

from pwndbg.lib.qemu import parse_qgdbserverversion


def test_parse_qgdbserverversion_empty():
    assert parse_qgdbserverversion(b"") is None
    assert parse_qgdbserverversion(b"E00") is None


def test_parse_qgdbserverversion_without_version():
    assert parse_qgdbserverversion(b"QEMU gdbserver version") is None


def test_parse_qgdbserverversion_with_full_version():
    assert parse_qgdbserverversion(b"QEMU gdbserver version: 10.1.0") == (10, 1, 0)
    assert parse_qgdbserverversion(b"10.1.2-rc1") == (10, 1, 2)


def test_parse_qgdbserverversion_with_partial_version():
    assert parse_qgdbserverversion(b"qemu 10.1") == (10, 1)
