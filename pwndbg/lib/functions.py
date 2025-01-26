from __future__ import annotations

from collections.abc import Mapping
from typing import List
from typing import NamedTuple


class Function(NamedTuple):
    type: str
    derefcnt: int
    name: str
    args: List[Argument]


class Argument(NamedTuple):
    type: str
    derefcnt: int
    name: str


class LazyFunctions(Mapping[str, Function]):
    def __init__(self, *args, **kw):
        self._raw_dict = {}

    def __getitem__(self, key):
        if not self._raw_dict:
            from pwndbg.lib.functions_data import load_functions

            # dict is empty because functions have not been loaded yet
            self._raw_dict.update(load_functions())
        return self._raw_dict.__getitem__(key)

    def __iter__(self):
        return iter(self._raw_dict)

    def __len__(self):
        return len(self._raw_dict)


functions = LazyFunctions()
