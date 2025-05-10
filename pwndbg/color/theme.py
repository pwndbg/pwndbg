from __future__ import annotations

from typing import Any
from typing import Sequence
from typing import List

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


# List of valid color names (functions defined in pwndbg.color.__init__)
VALID_COLOR_NAMES = [
    "none", "normal", "black", "red", "green", "yellow", "blue", "purple", "cyan",
    "light_gray", "foreground", "gray", "light_red", "light_green", "light_yellow", "light_blue",
    "light_purple", "light_cyan", "white", "bold", "underline"
]

def add_color_param(name: str, default: Any, set_show_doc: str, *, valid_colors: List[str] = None) -> Parameter:
    # Use the default list if not provided
    enum_sequence = valid_colors or VALID_COLOR_NAMES
    return config.add_param(
        name,
        default,
        set_show_doc,
        scope=Scope.theme,
        param_class=config.PARAM_ENUM,
        enum_sequence=enum_sequence,
    )
