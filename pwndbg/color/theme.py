from __future__ import annotations

from typing import Any
from typing import Sequence

from pwndbg import config
from pwndbg.lib.config import Parameter
from pwndbg.lib.config import Scope


class ColorParameter(Parameter):
    pass


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


def add_color_param(name: str, default: Any, set_show_doc: str) -> Parameter:
    return config.add_param_obj(ColorParameter(name, default, set_show_doc, scope=Scope.theme))
