from __future__ import annotations


class Constant(int):
    def __new__(cls, s, i):
        obj = super().__new__(cls, i)
        return obj
