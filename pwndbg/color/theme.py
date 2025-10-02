from __future__ import annotations

import sys
from typing import Any
from typing import Callable
from typing import Sequence

import pwndbg.color
from pwndbg import config
from pwndbg.lib.config import Parameter
from pwndbg.lib.config import Scope

VALID_COLORS = {
    "normal",
    "black",
    "red",
    "green",
    "yellow",
    "blue",
    "purple",
    "cyan",
    "light_gray",
    "foreground",
    "gray",
    "light_red",
    "light_green",
    "light_yellow",
    "light_blue",
    "light_purple",
    "light_cyan",
    "white",
    "bold",
    "underline",
}


class ColorParameter(Parameter):
    color_function: Callable[[object], str]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.update_color_function()

    def set(self, value: str) -> None:
        self.value = value
        self.update_color_function()

    def update_color_function(self):
        raw_color = str(self.value or "")

        parts = [p.strip() for p in raw_color.split(",") if p.strip()]
        valid_parts = []
        invalid_parts = []

        for p in parts:
            name = p.lower().replace("-", "_")
            if name == "none":
                continue
            if name in VALID_COLORS:
                valid_parts.append(p)
            else:
                invalid_parts.append(p)

        if invalid_parts and not valid_parts:
            for value in invalid_parts:
                sys.stderr.write(f"error: invalid color '{value}': expected color from {', '.join(sorted(VALID_COLORS))}\n")
            final = getattr(self, "_last_good_value", "normal")
            self.value = final

        else:
            for value in invalid_parts:
                sys.stderr.write(f"Invalid color '{value}' ignored\n")
            final = ",".join(valid_parts) or "normal"
            self.value = final
            self._last_good_value = final
        self.color_function = pwndbg.color.generateColorFunction(final)


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


def add_color_param(
    name: str, default: Any, set_show_doc: str, *, help_docstring: str = ""
) -> ColorParameter:
    color_parameter = ColorParameter(
        name, default, set_show_doc, help_docstring=help_docstring, scope=Scope.theme
    )

    config.triggers[name].append(color_parameter.update_color_function)

    config.add_param_obj(color_parameter)

    return color_parameter
