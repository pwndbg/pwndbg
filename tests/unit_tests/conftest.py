from __future__ import annotations

import importlib.abc
import sys


class RemoveReadlineFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "readline":
            raise ImportError("readline module disabled in unit tests")
        return None


sys.meta_path.insert(0, RemoveReadlineFinder())
