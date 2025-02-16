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
    flags: tuple[Flag, ...] | None = None


class Flag(NamedTuple):
    value: int
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


def format_flags_argument(flags: tuple[Flag, ...], value: int):
    original_value: int = value
    flag_names: List[str] = []

    # For some functions, some named flags are combinations
    # of other named flags. For example, the `mmap` flag
    # `MAP_SHARED_VALIDATE` is a combination of `MAP_SHARED`
    # and `MAP_PRIVATE`. As long as flags is ordered by
    # descending popcount, this loop will output more specific
    # flags.
    for flag in flags:
        if (value & flag.value) == flag.value:
            flag_names.append(flag.name)
            value = value & ~flag.value

    # If none of the known flags matched the value, just
    # format the value as a normal hex integer.
    if len(flag_names) == 0:
        return hex(original_value)

    # If we matched at least one known flag, but there
    # is some remaining un-matched portion of the value,
    # include that in the formatted | expression.
    if value != 0:
        flag_names.append(hex(value))

    # The final format includes the original value as hex,
    # any matched flags, and the left-over unmatched portion
    # of the integer.
    #
    # For example:
    # 0x03 (FLAG_2|0x01)
    return f"{original_value:#x} ({'|'.join(flag_names)})"
