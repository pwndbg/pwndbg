from __future__ import annotations

import pytest

from pwndbg.lib.mmap import FLAG_DICT
from pwndbg.lib.mmap import PROT_DICT
from pwndbg.lib.mmap import flag_from_string
from pwndbg.lib.mmap import prot_from_string
from pwndbg.lib.mmap import prot_to_string


@pytest.mark.parametrize(
    ("protstr", "expected"),
    [
        ("r", PROT_DICT["PROT_READ"]),
        ("Rx", PROT_DICT["PROT_READ"] | PROT_DICT["PROT_EXEC"]),
        ("3", PROT_DICT["PROT_READ"] | PROT_DICT["PROT_WRITE"]),
        ("PROT_read", PROT_DICT["PROT_READ"]),
        ("prot_read|PROT_WRITE", PROT_DICT["PROT_READ"] | PROT_DICT["PROT_WRITE"]),
        (
            "PROT_WRITE|PROT_EXEC|PROT_READ",
            PROT_DICT["PROT_READ"] | PROT_DICT["PROT_WRITE"] | PROT_DICT["PROT_EXEC"],
        ),
    ],
)
def test_prot_from_string(protstr: str, expected: int) -> None:
    assert prot_from_string(protstr) == expected


@pytest.mark.parametrize(
    ("prot", "expected"),
    [
        (PROT_DICT["PROT_READ"], "PROT_READ"),
        (PROT_DICT["PROT_READ"] | PROT_DICT["PROT_WRITE"], "PROT_READ|PROT_WRITE"),
    ],
)
def test_prot_to_str(prot: int, expected: str) -> None:
    assert prot_to_string(prot) == expected


@pytest.mark.parametrize(
    ("flagstr", "expected"),
    [
        ("1", FLAG_DICT["MAP_SHARED"]),
        ("MAP_PRIVATE|MAP_FIXED", FLAG_DICT["MAP_PRIVATE"] | FLAG_DICT["MAP_FIXED"]),
    ],
)
def test_flag_from_string(flagstr: str, expected: int) -> None:
    assert flag_from_string(flagstr) == expected
