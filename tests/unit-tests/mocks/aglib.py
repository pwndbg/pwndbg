from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

from mocks.arch import MockAmd64Arch
from mocks.config import Config
from mocks.typeinfo import Amd64TypeInfo


class AgLib(types.ModuleType):
    def __init__(self, module_name):
        super().__init__(module_name)

        self.config_mod = Config(module_name + ".config")
        self.arch = MockAmd64Arch(module_name + ".arch")
        self.typeinfo = Amd64TypeInfo(module_name + ".typeinfo")
        self.regs = MagicMock(__name__=module_name + ".regs")
        self.prompt = MagicMock(__name__=module_name + ".prompt")

        sys.modules[self.config_mod.__name__] = self.config_mod
        sys.modules[self.arch.__name__] = self.arch
        sys.modules[self.typeinfo.__name__] = self.typeinfo
        sys.modules[self.regs.__name__] = self.regs
        sys.modules[self.prompt.__name__] = self.prompt


module_name = "pwndbg.aglib"
module = AgLib(module_name)
sys.modules[module_name] = module

import pwndbg

pwndbg.aglib = sys.modules["pwndbg.aglib"]
