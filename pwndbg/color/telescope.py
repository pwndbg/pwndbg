from __future__ import annotations

from pwndbg import config
from pwndbg.color import generateColorFunction
from pwndbg.color import theme

offset_color = theme.add_color_param(
    "telescope-offset-color", "normal", "color of the telescope command (offset prefix)"
)
register_color = theme.add_color_param(
    "telescope-register-color", "bold", "color of the telescope command (register)"
)
offset_separator_color = theme.add_color_param(
    "telescope-offset-separator-color",
    "normal",
    "color of the telescope command (offset separator)",
)
offset_delimiter_color = theme.add_color_param(
    "telescope-offset-delimiter-color",
    "normal",
    "color of the telescope command (offset delimiter)",
)
repeating_marker_color = theme.add_color_param(
    "telescope-repeating-marker-color",
    "normal",
    "color of the telescope command (repeating values marker)",
)


def offset(x: object) -> str:
    return generateColorFunction(config.telescope_offset_color)(x)


def register(x: object) -> str:
    return generateColorFunction(config.telescope_register_color)(x)


def separator(x: object) -> str:
    return generateColorFunction(config.telescope_offset_separator_color)(x)


def delimiter(x: object) -> str:
    return generateColorFunction(config.telescope_offset_delimiter_color)(x)


def repeating_marker(x: object) -> str:
    return generateColorFunction(config.telescope_repeating_marker_color)(x)
