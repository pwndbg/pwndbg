from __future__ import annotations

from typing import Any
from typing import Callable
from typing import Sequence

import pwndbg.color
from pwndbg import config
from pwndbg.lib.config import Parameter
from pwndbg.lib.config import Scope


class ColorParameter(Parameter):
    color_function: Callable[[object], str]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.update_color_function()

    def update_color_function(self):
        self.color_function = pwndbg.color.generateColorFunction(self.value)


def add_param(
    name: str,
    default: Any,
    set_show_doc: str,
    *,
    help_docstring: str = "",
    param_class: int | None = None,
    enum_sequence: Sequence[str] | None = None,
) -> Parameter:
    return config.add_param(
        name,
        default,
        set_show_doc,
        scope=Scope.theme,
        help_docstring=help_docstring,
        param_class=param_class,
        enum_sequence=enum_sequence,
    )


def add_color_param(name: str, default: Any, set_show_doc: str) -> ColorParameter:
    color_parameter = ColorParameter(name, default, set_show_doc, scope=Scope.theme)

    config.triggers[name].append(color_parameter.update_color_function)

    config.add_param_obj(color_parameter)

    return color_parameter
