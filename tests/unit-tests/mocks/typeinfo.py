from __future__ import annotations

import types


class Amd64TypeInfo(types.ModuleType):
    def __init__(self, module_name):
        super().__init__(module_name)
        self.ptrsize = 8
