from __future__ import annotations

from pwndbg import config
from pwndbg.color import generateColorFunction
from pwndbg.color import theme

config_normal = theme.add_color_param(
    "hexdump-normal-color", "none", "color for hexdump command (normal bytes)"
)
config_printable = theme.add_color_param(
    "hexdump-printable-color", "bold", "color for hexdump command (printable characters)"
)
config_zero = theme.add_color_param(
    "hexdump-zero-color", "red", "color for hexdump command (zero bytes)"
)
config_special = theme.add_color_param(
    "hexdump-special-color", "yellow", "color for hexdump command (special bytes)"
)
config_offset = theme.add_color_param(
    "hexdump-offset-color", "none", "color for hexdump command (offset label)"
)
config_address = theme.add_color_param(
    "hexdump-address-color", "none", "color for hexdump command (address label)"
)
config_separator = theme.add_color_param(
    "hexdump-separator-color", "none", "color for hexdump command (group separator)"
)
config_highlight_group_lsb = theme.add_param(
    "hexdump-highlight-group-lsb",
    "underline",
    "highlight LSB of each group",
    help_docstring="Applies only if hexdump-use-big-endian actually changes byte order.",
)


def normal(x: str) -> str:
    return generateColorFunction(config.hexdump_normal_color)(x)


def printable(x: str) -> str:
    return generateColorFunction(config.hexdump_printable_color)(x)


def zero(x: str) -> str:
    return generateColorFunction(config.hexdump_zero_color)(x)


def special(x: str) -> str:
    return generateColorFunction(config.hexdump_special_color)(x)


def offset(x: str) -> str:
    return generateColorFunction(config.hexdump_offset_color)(x)


def address(x: str) -> str:
    return generateColorFunction(config.hexdump_address_color)(x)


def separator(x: str) -> str:
    return generateColorFunction(config.hexdump_separator_color)(x)


def highlight_group_lsb(x: str) -> str:
    return generateColorFunction(config.hexdump_highlight_group_lsb)(x)
