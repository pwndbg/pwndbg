from __future__ import annotations

from typing import Any

from pwndbg.config import config
from pwndbg.lib.config import Parameter


class ColorParameter(Parameter):
    pass


def add_param(name: str, default: Any, set_show_doc: str, color_param: bool = False) -> Parameter:
    return config.add_param(name, default, set_show_doc, scope="theme")

def add_color_param(name: str, default: Any, set_show_doc: str) -> Parameter:
    return config.add_param_obj(ColorParameter(name, default, set_show_doc, scope="theme"))
