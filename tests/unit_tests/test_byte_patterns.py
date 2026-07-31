from __future__ import annotations

import pytest

from pwndbg.lib.common import parse_byte_patterns


def test_parse_byte_patterns_exact_values() -> None:
    assert parse_byte_patterns("00") == {0x00}
    assert parse_byte_patterns("00,0a,ff") == {0x00, 0x0A, 0xFF}


def test_parse_byte_patterns_low_nibble_wildcard() -> None:
    assert parse_byte_patterns("4?") == set(range(0x40, 0x50))


def test_parse_byte_patterns_high_nibble_wildcard() -> None:
    assert parse_byte_patterns("?0") == {high << 4 for high in range(16)}


def test_parse_byte_patterns_both_nibbles_wildcard() -> None:
    assert parse_byte_patterns("??") == set(range(256))


def test_parse_byte_patterns_is_case_insensitive() -> None:
    assert parse_byte_patterns("AB,cD") == {0xAB, 0xCD}
    assert parse_byte_patterns("4?") == parse_byte_patterns("4?".upper())


def test_parse_byte_patterns_accepts_0x_prefix_and_whitespace() -> None:
    assert parse_byte_patterns("0x00, 0x0a , ff") == {0x00, 0x0A, 0xFF}


def test_parse_byte_patterns_deduplicates_overlapping_patterns() -> None:
    # 0x41 is matched by both patterns, but only ever counted once
    assert parse_byte_patterns("41,4?") == set(range(0x40, 0x50))


def test_parse_byte_patterns_rejects_wrong_length() -> None:
    with pytest.raises(ValueError, match="expected two hex nibbles"):
        parse_byte_patterns("0")

    with pytest.raises(ValueError, match="expected two hex nibbles"):
        parse_byte_patterns("000")


def test_parse_byte_patterns_rejects_empty_pattern() -> None:
    with pytest.raises(ValueError, match="Empty byte pattern"):
        parse_byte_patterns("")

    with pytest.raises(ValueError, match="Empty byte pattern"):
        parse_byte_patterns("00,,ff")


def test_parse_byte_patterns_rejects_non_hex_characters() -> None:
    with pytest.raises(ValueError, match="Invalid character"):
        parse_byte_patterns("zz")

    with pytest.raises(ValueError, match="Invalid character"):
        parse_byte_patterns("0g")
