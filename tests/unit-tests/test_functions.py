from __future__ import annotations

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
