from __future__ import annotations

from pwnlib.constants.constant import Constant

from pwndbg.lib.functions import format_flags_argument
from pwndbg.lib.functions import functions
from pwndbg.lib.functions_data import _functions


def test_functions_lookup():
    # test that the lazy loading through __getitem__ works properly
    key1 = next(iter(_functions.keys()))
    assert functions.get(key1) == _functions[key1]


def test_functions_lookup_does_not_exist():
    no_key = object()
    not_found = object()
    assert functions.get(no_key, not_found) is not_found


def test_format_flags_not_found():
    # None of the known flags are found in the value.
    flags = (
        Constant("FLAG_1", 0x01),
        Constant("FLAG_2", 0x02),
        Constant("FLAG_8", 0x08),
    )
    formatted = "0x4"
    assert format_flags_argument(flags, 0x4) == formatted


def test_format_flags_found():
    flags = (
        Constant("FLAG_3", 0x03),
        Constant("FLAG_1", 0x01),
        Constant("FLAG_2", 0x02),
        Constant("FLAG_8", 0x08),
    )
    formatted = "0xf (FLAG_3|FLAG_8|0x4)"
    assert format_flags_argument(flags, 0xF) == formatted
