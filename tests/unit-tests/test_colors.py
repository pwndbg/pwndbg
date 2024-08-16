from __future__ import annotations

from pwndbg.color import BOLD
from pwndbg.color import CYAN
from pwndbg.color import NORMAL
from pwndbg.color import cyan
from pwndbg.color import normal


def test_colors():
    s = "test"
    assert normal(s) == f"{NORMAL}{s}{NORMAL}"
    assert cyan(s) == f"{CYAN}{s}{NORMAL}"
    assert cyan(s, bold=True) == f"{BOLD}{CYAN}{s}{NORMAL}"
